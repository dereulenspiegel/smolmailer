package smolmailer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
	"github.com/mroth/jitter"
	"github.com/scaleway/scaleway-sdk-go/logger"
)

const retryQueueName = "retry-queue"

const maxRetries = 10

type Sender struct {
	cfg        *Config
	q          GenericQueue[*QueuedMessage]
	retryQueue GenericQueue[*QueuedMessage]
	logger     *slog.Logger

	ctx       context.Context
	ctxCancel context.CancelFunc

	retryCancel context.CancelFunc

	mxResolver func(string) ([]*net.MX, error)
	mxPorts    []int

	defaultDialer *net.Dialer

	dkimOptions *dkim.SignOptions
}

func NewSender(ctx context.Context, logger *slog.Logger, cfg *Config, q GenericQueue[*QueuedMessage]) (*Sender, error) {
	bCtx, cancel := context.WithCancel(ctx)
	retryCtx, retryCancel := context.WithCancel(ctx)
	retryQueue, err := NewGenericPersistentQueue[*QueuedMessage](retryQueueName, cfg.QueuePath, 50)
	if err != nil {
		cancel()
		retryCancel()
		return nil, fmt.Errorf("failed to create retry queue: %w", err)
	}
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
		retryCancel()
		return nil, errors.New("no dkim config specified")
	}
	dkimKey, err := parseDkimKey(cfg.Dkim.PrivateKey)
	if err != nil {
		cancel()
		retryCancel()
		return nil, fmt.Errorf("invalid dkim key: %w", err)
	}

	dkimRecordValue, err := dkimTxtRecordContent(dkimKey)
	if err == nil {
		dkimDomain := dkimDomain(cfg.Dkim.Selector, cfg.Domain)
		logger.Info("Please add the following record to your DNS zone", "domain", dkimDomain, "recordValue", dkimRecordValue)
	}

	s := &Sender{
		ctx:           bCtx,
		ctxCancel:     cancel,
		retryCancel:   retryCancel,
		q:             q,
		retryQueue:    retryQueue,
		cfg:           cfg,
		mxResolver:    lookupMX,
		logger:        logger,
		mxPorts:       []int{25, 465, 587},
		defaultDialer: dialer,
		dkimOptions: &dkim.SignOptions{
			Domain:   cfg.Domain,
			Selector: cfg.Dkim.Selector,
			Signer:   dkimKey,
			Hash:     crypto.SHA256,
			HeaderKeys: []string{ // Recommended headers according to https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.1
				"From", "Reply-to", "Subject", "Date", "To", "Cc", "Resent-Date", "Resent-From", "Resent-To", "Resent-Cc", "In-Reply-To", "References",
				"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
			},
		},
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
			for msg, err := s.retryQueue.Receive(); err == nil; {
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
			if err == ErrQueueEmpty {
				continue
			} else if err != nil {
				s.logger.Error("failed to read from queue", "err", err)
				continue
			}
			logger.Infof("processing message", "from", msg.From, "to", msg.To, "envelopeId", msg.MailOpts.EnvelopeID)
			go func(msg *QueuedMessage) {
				if msg.MailOpts == nil {
					// TODO generate envelope id if missing
					msg.MailOpts = &smtp.MailOptions{}
				}
				logger := s.logger.With("from", msg.From, "msgid", msg.MailOpts.EnvelopeID)

				signedBuf := &bytes.Buffer{}
				if err := dkim.Sign(signedBuf, bytes.NewReader(msg.Body), s.dkimOptions); err != nil {
					logger.Error("failed to sign message", "err", err)
				}
				msg.Body = signedBuf.Bytes()
				logger.Info("trying to send message")
				go s.trySend(msg)
			}(msg)
		}
	}
}

func (s *Sender) trySend(msg *QueuedMessage) {
	logger := s.logger.With("from", msg.From, "to", msg.To, "envelopeId", msg.MailOpts.EnvelopeID)
	err := s.sendMail(msg)
	if err != nil {

		msg.LastErr = err
		msg.ErrorCount++
		logger.Error("failed to deliver mail", "err", err, "errorCount", msg.ErrorCount)
		if msg.ErrorCount >= maxRetries {
			logger.Error("giving up delivering mail", "errorCount", msg.ErrorCount, "err", err)
		}
		if err := s.retryQueue.Send(msg); err != nil {
			logger.Error("failed to enqueue message")
		}
	}
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
		tlsConfig := &tls.Config{ServerName: host}

		switch port {
		case 25:
			dialFuncs = append(dialFuncs, dialStartTls(logger, tlsConfig, address))
		case 587, 465:
			dialFuncs = append(dialFuncs, dialTls(logger, tlsConfig, address))
		default:
			dialFuncs = append(dialFuncs, dialSmpt(logger, address))
		}
		if c != nil {
			logger.Info("succeeded dialing mx host")
			c.SubmissionTimeout = time.Second * 10
			return c, nil
		}
	}
	return resolveParallel(dialFuncs...)
}

func (s *Sender) smtpDialog(c *smtp.Client, msg *QueuedMessage) error {
	if err := c.Hello(s.cfg.Domain); err != nil {
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

func (s *Sender) sendMail(msg *QueuedMessage) error {
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

func parseDkimKey(base64String string) (crypto.Signer, error) {
	// To be able to store this in env vars, we base64 encode it
	pemString, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode pem string: %w", err)
	}
	block, _ := pem.Decode(pemString)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM string")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return key.(ed25519.PrivateKey), err
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
	}
}

func pubKey(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privKey.(type) {
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *rsa.PrivateKey:
		return k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}

func dnsDkimKey(publicKey crypto.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to DER encode public key: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(pubkeyBytes), nil
}

func dkimTxtRecordContent(privateKey crypto.PrivateKey) (string, error) {
	pubKey, err := pubKey(privateKey)
	if err != nil {
		return "", err
	}
	base64Key, err := dnsDkimKey(pubKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v=DKIM1;p=%s", base64Key), nil
}

func dkimDomain(selector, domain string) string {
	return fmt.Sprintf("%s._domainkey.%s", selector, domain)
}
