package smolmailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/joncrlsn/dque"
	"github.com/mroth/jitter"
)

const retryQueueName = "retry-queue"

const maxRetries = 10

type senderQueue interface {
	Receive() (*QueuedMessage, error)
}

type Sender struct {
	cfg        *Config
	q          senderQueue
	retryQueue *dque.DQue
	logger     *slog.Logger

	ctx       context.Context
	ctxCancel context.CancelFunc

	retryCancel context.CancelFunc

	mxResolver func(string) ([]*net.MX, error)
	mxPorts    []int
}

func NewSender(ctx context.Context, logger *slog.Logger, cfg *Config, q senderQueue) (*Sender, error) {
	bCtx, cancel := context.WithCancel(ctx)
	retryCtx, retryCancel := context.WithCancel(ctx)
	retryQueue, err := dque.NewOrOpen(retryQueueName, cfg.QueuePath, 50, func() interface{} {
		return &QueuedMessage{}
	})
	if err != nil {
		cancel()
		retryCancel()
		return nil, fmt.Errorf("failed to create retry queue: %w", err)
	}
	s := &Sender{
		ctx:         bCtx,
		ctxCancel:   cancel,
		retryCancel: retryCancel,
		q:           q,
		retryQueue:  retryQueue,
		cfg:         cfg,
		mxResolver:  lookupMX,
		logger:      logger,
		mxPorts:     []int{465, 587, 25},
	}
	go s.run()
	go s.runRetry(retryCtx)
	return s, nil
}

func (s *Sender) Close() error {
	qErr := s.retryQueue.Close()
	s.ctxCancel()
	s.retryCancel()
	return errors.Join(qErr)
}

func (s *Sender) runRetry(ctx context.Context) {
	ticker := jitter.NewTicker(time.Minute*5, 0.1)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for item, err := s.retryQueue.Dequeue(); err == nil; {
				msg := item.(*QueuedMessage)
				s.trySend(msg)
			}
		}
	}
}

func (s *Sender) run() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			msg, err := s.q.Receive()
			if err == dque.ErrEmpty {
				continue
			}
			go s.trySend(msg)
		}
	}
}

func (s *Sender) trySend(msg *QueuedMessage) {
	err := s.sendMail(msg)
	if err != nil {
		msg.LastErr = err
		msg.ErrorCount++
		if msg.ErrorCount >= maxRetries {
			// TODO log error and discard message
		}
		s.retryQueue.Enqueue(msg)
	}
}

func (s *Sender) dialHost(host string) (c *smtp.Client, err error) {
	logger := s.logger.With("host", host)
	errs := []error{}
	for _, port := range s.mxPorts {
		logger := logger.With("port", port)
		address := fmt.Sprintf("%s:%d", host, port)
		tlsConfig := &tls.Config{ServerName: host}

		switch port {
		case 465:
			{
				//SMTPS
				c, err = smtp.DialTLS(address, tlsConfig)
				if err != nil {
					logger.Error("failed to dial tls", "err", err)
					errs = append(errs, err)
					continue
				}
			}
		case 587:
			c, err = smtp.DialStartTLS(address, &tls.Config{ServerName: host})
			if err != nil {
				logger.Error("failed to dial start tls", "err", err)
				errs = append(errs, err)
				continue
			}
		case 25:
			c, err = smtp.Dial(address)

			if err != nil {
				logger.Error("failed to dial smtp", "err", err)
				errs = append(errs, err)
				continue
			}
		default:
			// Assume smtp for testing
			c, err = smtp.Dial(address)
			if err != nil {
				logger.Error("failed to dial smtp", "err", err)
				errs = append(errs, err)
				continue
			}
		}
		if c != nil {
			return c, nil
		}
	}
	err = errors.Join(errs...)
	return
}

func (s *Sender) smtpDialog(c *smtp.Client, msg *QueuedMessage) error {
	if err := c.Hello(s.cfg.Domain); err != nil {
		c.Close()
		return fmt.Errorf("hello cmd failed: %w", err)
	}

	if err := c.Mail(msg.From, &smtp.MailOptions{
		RequireTLS: false,
	}); err != nil {
		c.Close()
		return fmt.Errorf("mail cmd failed: %w", err)
	}

	if err := c.Rcpt(msg.To, &smtp.RcptOptions{}); err != nil {
		c.Close()
		return fmt.Errorf("rcpt cmd failed: %w", err)
	}

	if w, err := c.Data(); err != nil {
		c.Close()
		return fmt.Errorf("data cmd failed: %w", err)
	} else {
		if n, err := w.Write(msg.Body); err != nil {
			w.Close()
			c.Close()
			return err
		} else if n != len(msg.Body) {
			// TODO define error
			w.Close()
			c.Close()
			return fmt.Errorf("failed to write all data")
		}
		w.Close()
	}
	return c.Quit()
}

func (s *Sender) sendMail(msg *QueuedMessage) error {
	logger := s.logger.With("func", "sendMail", "to", msg.To, "from", msg.From)
	msg.LastDeliveryAttempt = time.Now()
	domain := strings.Split(msg.To, "@")[1]

	mxRecords, err := s.mxResolver(domain)
	if err != nil {
		return err
	}
	slices.SortStableFunc(mxRecords, func(mx1, mx2 *net.MX) int {
		return int(mx1.Pref) - int(mx2.Pref)
	})

	for _, mx := range mxRecords {
		host := mx.Host

		c, err := s.dialHost(host)
		if err != nil {
			logger.Error("failed to dial host", "err", err)
			continue
		}

		if err := s.smtpDialog(c, msg); err != nil {
			logger.Error("smtp dialog failed", "err", err)
			continue
		}

		return nil

	}
	return fmt.Errorf("failed to deliver email to %s", msg.To)
}

func lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup mx records for %s:%w", domain, err)
	}
	return mxRecords, nil
}
