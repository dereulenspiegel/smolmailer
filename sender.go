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

	defaultDialer *net.Dialer

	dkimOptions *dkim.SignOptions
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
		mxPorts:       []int{465, 587},
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

				go s.trySend(msg)
			}(msg)
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
		case 587:
			tlsDialer := tls.Dialer{
				NetDialer: s.defaultDialer,
				Config:    tlsConfig,
			}
			conn, err := tlsDialer.Dial("tcp", address)
			if err != nil {
				logger.Error("failed to tls dial", "port", port, "err", err)
				errs = append(errs, err)
				continue
			}
			c = smtp.NewClient(conn)
		case 465:

			tlsDialer := tls.Dialer{
				NetDialer: s.defaultDialer,
				Config:    tlsConfig,
			}
			conn, err := tlsDialer.Dial("tcp", address)
			if err != nil {
				logger.Error("failed to tls dial", "port", port, "err", err)
				continue
			}
			c = smtp.NewClient(conn)

		default:
			conn, err := s.defaultDialer.Dial("tcp", address)
			if err != nil {
				logger.Error("failed to dial smtp", "err", err)
				errs = append(errs, err)
				continue
			}
			// Assume smtp for testing
			c = smtp.NewClient(conn)

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
	logger := s.logger.With("func", "sendMail", "to", msg.To, "from", msg.From)
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

func parseDkimKey(pemString string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemString))
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
