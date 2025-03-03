package sender

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

	"github.com/dereulenspiegel/smolmailer/internal/config"
	"github.com/dereulenspiegel/smolmailer/internal/queue"
	"github.com/dereulenspiegel/smolmailer/internal/utils"
	"github.com/emersion/go-smtp"
)

const maxRetries = 10

type Sender struct {
	cfg    *config.Config
	q      queue.GenericWorkQueue[*queue.QueuedMessage]
	logger *slog.Logger

	ctx       context.Context
	ctxCancel context.CancelFunc

	mxResolver func(string) ([]*net.MX, error)
	mxPorts    []int

	defaultDialer *net.Dialer
}

func NewSender(ctx context.Context, logger *slog.Logger, cfg *config.Config, q queue.GenericWorkQueue[*queue.QueuedMessage]) (*Sender, error) {
	bCtx, cancel := context.WithCancel(ctx)

	dialer := &net.Dialer{
		Timeout: time.Second * 30,
	}

	if cfg.SendAddr != "" {
		sendIp := net.ParseIP(cfg.SendAddr)
		dialer.LocalAddr = &net.TCPAddr{
			IP:   sendIp,
			Port: 0,
		}
	}

	if cfg.Dkim == nil {
		cancel()
		return nil, errors.New("no dkim config specified")
	}

	s := &Sender{
		ctx:           bCtx,
		ctxCancel:     cancel,
		q:             q,
		cfg:           cfg,
		mxResolver:    lookupMX,
		logger:        logger,
		mxPorts:       []int{25, 465, 587},
		defaultDialer: dialer,
	}
	if cfg.TestingOpts != nil {
		s.mxPorts = cfg.TestingOpts.MxPorts
		s.mxResolver = cfg.TestingOpts.MxResolv
	}
	go s.run()
	return s, nil
}

func (s *Sender) Close() error {
	s.ctxCancel()
	return nil
}

func (s *Sender) run() {

	if err := s.q.Consume(s.ctx, s.trySend); err != nil {
		s.logger.Error("failed to consume queue", "err", err)
		return
	}
}

const defaultRetryPeriod = time.Minute * 4

func (s *Sender) trySend(ctx context.Context, msg *queue.QueuedMessage) error {
	if msg.MailOpts == nil {
		// TODO generate envelope id if missing
		msg.MailOpts = &smtp.MailOptions{}
	}
	logger := s.logger.With("from", msg.From, "to", msg.To, "msgid", msg.MailOpts.EnvelopeID)
	logger.Info("sending mail")

	err := s.sendMail(msg)
	if err != nil {
		msg.LastErr = err
		msg.ErrorCount++
		logger.Error("failed to deliver mail", "err", err, "errorCount", msg.ErrorCount)
		if msg.ErrorCount >= maxRetries {
			logger.Error("giving up delivering mail", "errorCount", msg.ErrorCount, "err", err)
		}
		attempts := maxRetries - msg.ErrorCount
		if err := s.q.Queue(s.ctx, msg, queue.QueueWithAttempts(attempts), queue.QueueAfter(defaultRetryPeriod)); err != nil {
			logger.Error("failed to requeue failed message", "err", err)
		}
	}
	return nil
}

func (s *Sender) dialHost(host string) (c *smtp.Client, err error) {
	logger := s.logger.With("host", host)
	logger.Info("dialing mx host")
	errs := []error{}

	dialTls := func(logger *slog.Logger, tlsConfig *tls.Config, address string) func() (*smtp.Client, error) {
		return func() (*smtp.Client, error) {
			tlsDialer := tls.Dialer{
				NetDialer: s.defaultDialer,
				Config:    tlsConfig,
			}
			conn, err := tlsDialer.Dial("tcp", address)
			if err != nil {
				logger.Error("failed to tls dial", "adress", address, "err", err)
				errs = append(errs, err)
			}
			return smtp.NewClient(conn), nil
		}
	}

	dialStartTls := func(logger *slog.Logger, tlsConfig *tls.Config, address string) func() (*smtp.Client, error) {
		return func() (*smtp.Client, error) {
			conn, err := s.defaultDialer.Dial("tcp", address)
			if err != nil {
				errs = append(errs, err)
				logger.Error("failed to dial for start TLS", "err", err)
				return nil, err
			}
			return smtp.NewClientStartTLS(conn, tlsConfig)
		}
	}

	dialSmpt := func(logger *slog.Logger, address string) func() (*smtp.Client, error) {
		return func() (*smtp.Client, error) {
			conn, err := s.defaultDialer.Dial("tcp", address)
			if err != nil {
				errs = append(errs, err)
				logger.Error("failed to dial smtp", "err", err)
				return nil, err
			}
			// Assume smtp for testing
			c = smtp.NewClient(conn)
			return c, nil
		}
	}

	dialFuncs := []func() (*smtp.Client, error){}
	for _, port := range s.mxPorts {
		logger := logger.With("port", port)
		address := fmt.Sprintf("%s:%d", host, port)
		tlsConfig := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}

		switch port {
		case 25:
			dialFuncs = append(dialFuncs, dialStartTls(logger, tlsConfig, address))
			dialFuncs = append(dialFuncs, dialTls(logger, tlsConfig, address))
			dialFuncs = append(dialFuncs, dialSmpt(logger, address))
		case 587, 465:
			dialFuncs = append(dialFuncs, dialTls(logger, tlsConfig, address))
			dialFuncs = append(dialFuncs, dialStartTls(logger, tlsConfig, address))
		default:
			dialFuncs = append(dialFuncs, dialSmpt(logger, address))
		}
		if c != nil {
			logger.Info("succeeded dialing mx host")
			c.SubmissionTimeout = time.Second * 10
			return c, nil
		}
	}
	return utils.ResolveParallel(dialFuncs...)
}

func (s *Sender) smtpDialog(c *smtp.Client, msg *queue.QueuedMessage) error {
	if err := c.Hello(s.cfg.MailDomain); err != nil {
		c.Close()
		return fmt.Errorf("hello cmd failed: %w", err)
	}

	if err := c.Mail(msg.From, msg.MailOpts); err != nil {
		c.Close()
		return fmt.Errorf("mail cmd failed: %w", err)
	}

	if err := c.Rcpt(msg.To, msg.RcptOpt); err != nil {
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

func (s *Sender) sendMail(msg *queue.QueuedMessage) error {
	logger := s.logger.With("to", msg.To, "from", msg.From, "envelopeId", msg.MailOpts.EnvelopeID)
	msg.LastDeliveryAttempt = time.Now()
	domain := strings.Split(msg.To, "@")[1]

	mxRecords, err := s.mxResolver(domain)
	if err != nil {
		return err
	}

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
		logger.Info("Successfully delivered message")
		return nil

	}
	return fmt.Errorf("failed to deliver email to %s", msg.To)
}

func lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup mx records for %s:%w", domain, err)
	}
	slices.SortStableFunc(mxRecords, func(mx1, mx2 *net.MX) int {
		return int(mx1.Pref) - int(mx2.Pref)
	})
	return mxRecords, nil
}
