package smolmailer

import (
	"context"
	"crypto"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

type Server struct {
	ctx        context.Context
	smtpServer *smtp.Server

	receiveQueue     GenericWorkQueue[*ReceivedMessage]
	sendQueue        GenericWorkQueue[*QueuedMessage]
	processorHandler *PreprocessorHandler
	sender           *Sender

	backendCtx    context.Context
	backendCancel context.CancelFunc
	ctxSender     context.Context
	senderCancel  context.CancelFunc

	cfg    *Config
	logger *slog.Logger
}

func NewServer(ctx context.Context, logger *slog.Logger, cfg *Config) (*Server, error) {

	s := &Server{
		cfg:    cfg,
		logger: logger,
	}
	if err := os.MkdirAll(cfg.QueuePath, 0770); err != nil {
		logger.Error("failed to ensure queue folder exists", "err", err, "queuePath", cfg.QueuePath)
		return nil, fmt.Errorf("failed to ensure queue folder exists: %w", err)
	}

	liteDb, err := sql.Open("sqlite3", filepath.Join(cfg.QueuePath, "mail.queue"))
	if err != nil {
		logger.Error("failed to open sqlite queue db", "err", err)
		return nil, fmt.Errorf("failed to open sqlite queue db: %w", err)
	}

	s.receiveQueue, err = NewSQLiteWorkQueueOnDb[*ReceivedMessage](liteDb, "receive.queue", 10, 300)
	if err != nil {
		logger.Error("failed to create receive queue", "err", err)
		return nil, fmt.Errorf("failed to create receive queue: %w", err)
	}
	s.sendQueue, err = NewSQLiteWorkQueueOnDb[*QueuedMessage](liteDb, "send.queue", 10, 300)
	if err != nil {
		logger.Error("failed to create send queue", "err", err)
		return nil, fmt.Errorf("failed to create send queue: %w", err)
	}

	dkimKey, err := ParseDkimKey(cfg.Dkim.PrivateKey)
	if err != nil {
		logger.Error("failed to parse DKIM key", "err", err)
		return nil, fmt.Errorf("failed to parse DKIM key: %w", err)
	}
	dkimRecordValue, err := DkimTxtRecordContent(dkimKey)
	if err == nil {
		dkimDomain := DkimDomain(cfg.Dkim.Selector, cfg.MailDomain)
		if err := VerifyDKIMRecords(dkimDomain, dkimRecordValue); err == ErrNoDKIMRecord {
			logger.Warn("Please add the following record to your DNS zone", "domain", dkimDomain, "recordValue", dkimRecordValue)
		} else if err != nil {
			logger.Error("failed to resolve and verify DKIM record", "err", err)
		}
	}
	if err := VerifySPFRecord(cfg.MailDomain, cfg.TlsDomain, cfg.SendAddr); err != nil {
		logger.Warn("spf records are not properly setup", "err", err)
	}

	s.processorHandler, err = NewProcessorHandler(ctx, logger.With("component", "messageProcessing"), s.receiveQueue,
		WithReceiveProcessors(DkimProcessor(&dkim.SignOptions{
			Domain:   cfg.MailDomain,
			Selector: cfg.Dkim.Selector,
			Signer:   dkimKey,
			Hash:     crypto.SHA256,
			HeaderKeys: []string{ // Recommended headers according to https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.1
				"From", "Reply-to", "Subject", "Date", "To", "Cc", "Resent-Date", "Resent-From", "Resent-To", "Resent-Cc", "In-Reply-To", "References",
				"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
			},
		})),
		WithPreSendProcessors(SendProcessor(ctx, s.sendQueue, QueueWithAttempts(3))))
	if err != nil {
		logger.Error("failed to create message processing", "err", err)
		return nil, fmt.Errorf("failed to create message processing: %w", err)
	}

	userSrv, err := NewUserService(logger.With("component", "UserService"), cfg.UserFile)
	if err != nil {
		logger.Error("failed to create user service", "err", err)
		return nil, fmt.Errorf("failed to create user service: %w", err)
	}

	s.backendCtx, s.backendCancel = context.WithCancel(ctx)
	backend, err := NewBackend(s.backendCtx, logger.With("component", "backend"), s.receiveQueue, userSrv, cfg)
	if err != nil {
		logger.Error("failed to create backend", "err", err)
		return nil, fmt.Errorf("failed to create backend: %w", err)
	}

	smtpServer := smtp.NewServer(backend)
	smtpServer.Domain = cfg.MailDomain
	smtpServer.Addr = cfg.ListenAddr
	smtpServer.WriteTimeout = 10 * time.Second
	smtpServer.ReadTimeout = 10 * time.Second
	smtpServer.MaxMessageBytes = 1024 * 1024
	smtpServer.MaxRecipients = 2
	smtpServer.AllowInsecureAuth = !cfg.ListenTls
	smtpServer.EnableREQUIRETLS = cfg.ListenTls
	smtpServer.ErrorLog = NewSlogLogger(ctx, logger.With("component", "smtp-server"), slog.LevelError)

	if cfg.ListenTls {
		acmeTls, err := acme.NewAcme(ctx, logger.With("component", "acme"), cfg.Acme)
		if err != nil {
			logger.Error("failed to create ACME setup", "err", err)
			panic(err)
		}
		if err := acmeTls.ObtainCertificate(cfg.TlsDomain); err != nil {
			logger.Error("failed to obtain certificate for domain", "domain", cfg.TlsDomain, "err", err)
			panic(err)
		}
		smtpServer.TLSConfig = acme.NewTlsConfig(acmeTls)
	}
	s.smtpServer = smtpServer

	s.ctxSender, s.senderCancel = context.WithCancel(ctx)
	s.sender, err = NewSender(s.ctxSender, logger.With("component", "sender"), cfg, s.sendQueue)
	if err != nil {
		logger.Error("failed to create sender", "err", err)
		return nil, fmt.Errorf("failed to create sender: %w", err)
	}
	return s, nil
}

func (s *Server) Serve() error {
	if s.cfg.ListenTls {
		if err := s.smtpServer.ListenAndServeTLS(); err != nil {
			s.logger.Error("failed to listen with TLS on addr", "err", err, "addr", s.cfg.ListenAddr)
			return err
		}
	} else {
		if err := s.smtpServer.ListenAndServe(); err != nil {
			s.logger.Error("failed to listen on addr", "err", err, "addr", s.cfg.ListenAddr)
			return err
		}
	}
	return nil
}

func (s *Server) Close() error {
	errs := []error{}
	if err := s.smtpServer.Close(); err != nil {
		errs = append(errs, err)
	}
	s.backendCancel()
	if err := s.sender.Close(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(s.ctx, time.Second*30)
	defer cancel()
	errs := []error{}
	if err := s.smtpServer.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	s.backendCancel()
	if err := s.sender.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
