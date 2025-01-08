package smolmailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

type smtpForwarder interface {
	Send(*Session) error
}

type Sender struct {
	cfg        *Config
	q          senderQueue
	retryQueue *dque.DQue

	ctx       context.Context
	ctxCancel context.CancelFunc

	retryCancel context.CancelFunc
}

func NewSender(ctx context.Context, cfg *Config, q senderQueue) (*Sender, error) {
	bCtx, cancel := context.WithCancel(ctx)
	retryCtx, retryCancel := context.WithCancel(ctx)
	retryQueue, err := dque.NewOrOpen(retryQueueName, cfg.QueuePath, 50, func() interface{} {
		return &QueuedMessage{}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create retry queue: %w", err)
	}
	s := &Sender{
		ctx:         bCtx,
		ctxCancel:   cancel,
		retryCancel: retryCancel,
		q:           q,
		retryQueue:  retryQueue,
		cfg:         cfg,
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
	errs := []error{}
	for _, port := range []int{587, 465, 25} {
		address := fmt.Sprintf("%s:%d", host, port)
		tlsConfig := &tls.Config{ServerName: host}

		switch port {
		case 465:
			{
				//SMTPS
				c, err = smtp.DialTLS(address, tlsConfig)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}
		case 587:
			c, err = smtp.DialStartTLS(address, &tls.Config{ServerName: host})
			if err != nil {
				errs = append(errs, err)
				continue
			}
		case 25:
			c, err = smtp.Dial(address)

			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
	}
	err = errors.Join(errs...)
	return
}

func (s *Sender) smtpDialog(c *smtp.Client, msg *QueuedMessage) error {
	if err := c.Hello(s.cfg.Domain); err != nil {
		c.Close()
		return err
	}

	if err := c.Mail(msg.From, &smtp.MailOptions{
		RequireTLS: true,
	}); err != nil {
		c.Close()
		return err
	}

	if err := c.Rcpt(msg.To, &smtp.RcptOptions{}); err != nil {
		c.Close()
		return err
	}

	if w, err := c.Data(); err != nil {
		c.Close()
		return err
	} else {
		if n, err := w.Write(msg.Body); err != nil {
			c.Close()
			return err
		} else if n != len(msg.Body) {
			// TODO define error
			c.Close()
			return fmt.Errorf("failed to write all data")
		}
	}
	return c.Quit()
}

func (s *Sender) sendMail(msg *QueuedMessage) error {
	msg.LastDeliveryAttempt = time.Now()
	domain := strings.Split(msg.To, "@")[1]

	mxRecords, err := lookupMX(domain)
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
			// TODO log error
			continue
		}

		if err := s.smtpDialog(c, msg); err != nil {
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
