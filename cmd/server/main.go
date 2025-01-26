package main

import (
	"context"
	"crypto"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dereulenspiegel/smolmailer"
	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
	"github.com/spf13/viper"

	_ "github.com/mattn/go-sqlite3"
)

var (
	logLevel = new(slog.LevelVar)
)

func main() {
	ctx := context.Background()
	ctxSender, senderCancel := context.WithCancel(ctx)
	defer senderCancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		smolmailer.ConfigDefaults()
		if err := viper.ReadInConfig(); err != nil && !errors.Is(err, &viper.ConfigFileNotFoundError{}) {
			logger.Warn("failed to read config", "err", err)
		}
		cfg := &smolmailer.Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			logger.Warn("failed to unmarshal config", "err", err)
			panic(err)
		}
		if err := cfg.IsValid(); err != nil {
			logger.Error("invalid/incomplete configuration", "err", err)
			panic(err)
		}
		if err := logLevel.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
			logger.Error("failed to unmarshal log level", "err", err)
			panic(err)
		}

		if err := os.MkdirAll(cfg.QueuePath, 0770); err != nil {
			logger.Error("failed to ensure queue folder exists", "err", err, "queuePath", cfg.QueuePath)
			panic(err)
		}

		liteDb, err := sql.Open("sqlite3", filepath.Join(cfg.QueuePath, "mail.queue"))
		if err != nil {
			logger.Error("failed to open sqlite queue db", "err", err)
			panic(err)
		}

		receiveQueue, err := smolmailer.NewSQLiteWorkQueueOnDb[*smolmailer.ReceivedMessage](liteDb, "receive.queue", 10, 300)
		if err != nil {
			logger.Error("failed to create receive queue", "err", err)
			panic(err)
		}
		sendQueue, err := smolmailer.NewSQLiteWorkQueueOnDb[*smolmailer.QueuedMessage](liteDb, "send.queue", 10, 300)
		if err != nil {
			logger.Error("failed to create receive queue", "err", err)
			panic(err)
		}

		dkimKey, err := smolmailer.ParseDkimKey(cfg.Dkim.PrivateKey)
		if err != nil {
			logger.Error("failed to parse DKIM key", "err", err)
			panic(err)
		}
		dkimRecordValue, err := smolmailer.DkimTxtRecordContent(dkimKey)
		if err == nil {
			dkimDomain := smolmailer.DkimDomain(cfg.Dkim.Selector, cfg.Domain)
			logger.Info("Please add the following record to your DNS zone", "domain", dkimDomain, "recordValue", dkimRecordValue)
		}
		_, err = smolmailer.NewProcessorHandler(ctx, logger.With("component", "messageProcessing"), receiveQueue,
			smolmailer.WithReceiveProcessors(smolmailer.DkimProcessor(&dkim.SignOptions{
				Domain:   cfg.Domain,
				Selector: cfg.Dkim.Selector,
				Signer:   dkimKey,
				Hash:     crypto.SHA256,
				HeaderKeys: []string{ // Recommended headers according to https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.1
					"From", "Reply-to", "Subject", "Date", "To", "Cc", "Resent-Date", "Resent-From", "Resent-To", "Resent-Cc", "In-Reply-To", "References",
					"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
				},
			})),
			smolmailer.WithPreSendProcessors(smolmailer.SendProcessor(ctx, sendQueue, smolmailer.QueueWithAttempts(3))))
		if err != nil {
			logger.Error("failed to create message processing", "err", err)
			panic(err)
		}

		userSrv, err := smolmailer.NewUserService(logger.With("component", "UserService"), cfg.UserFile)
		if err != nil {
			logger.Error("failed to create user service", "err", err)
			panic(err)
		}
		backendCtx, backendCancel := context.WithCancel(ctx)
		defer backendCancel()
		b, err := smolmailer.NewBackend(backendCtx, logger.With("component", "backend"), receiveQueue, userSrv, cfg)
		if err != nil {
			logger.Error("failed to create backend", "err", err)
			panic(err)
		}

		s := smtp.NewServer(b)
		s.Domain = cfg.Domain
		s.Addr = cfg.ListenAddr
		s.WriteTimeout = 10 * time.Second
		s.ReadTimeout = 10 * time.Second
		s.MaxMessageBytes = 1024 * 1024
		s.MaxRecipients = 2
		s.AllowInsecureAuth = !cfg.ListenTls
		s.EnableREQUIRETLS = cfg.ListenTls
		s.ErrorLog = smolmailer.NewSlogLogger(ctx, logger.With("component", "smtp-server"), slog.LevelError)

		if cfg.ListenTls {
			acmeTls, err := acme.NewAcme(ctx, logger.With("component", "acme"), cfg.Acme)
			if err != nil {
				logger.Error("failed to create ACME setup", "err", err)
				panic(err)
			}
			if err := acmeTls.ObtainCertificate(cfg.Domain); err != nil {
				logger.Error("failed to obtain certificate for domain", "domain", cfg.Domain, "err", err)
				panic(err)
			}
			s.TLSConfig = acme.NewTlsConfig(acmeTls)
		}

		sender, err := smolmailer.NewSender(ctxSender, logger.With("component", "sender"), cfg, sendQueue)
		if err != nil {
			logger.Error("failed to create sender", "err", err)
			panic(err)
		}

		if cfg.ListenTls {
			if err := s.ListenAndServeTLS(); err != nil {
				logger.Error("failed to listen with TLS on addr", "err", err, "addr", cfg.ListenAddr)
			}
		} else {
			if err := s.ListenAndServe(); err != nil {
				logger.Error("failed to listen on addr", "err", err, "addr", cfg.ListenAddr)
			}
		}
		sender.Close()
	}()

	<-sigs
	logger.Info("shutting down")
}
