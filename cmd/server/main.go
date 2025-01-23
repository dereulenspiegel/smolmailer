package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dereulenspiegel/smolmailer"
	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/emersion/go-smtp"
	"github.com/spf13/viper"
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
			panic(err)
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

		q, err := smolmailer.NewSQLiteWorkQueue[*smolmailer.QueuedMessage](filepath.Join(cfg.QueuePath, "queue.db"), "send.queue", 10, 300)
		if err != nil {
			logger.Error("failed to create queue", "err", err)
			panic(err)
		}
		backendCtx, backendCancel := context.WithCancel(ctx)
		defer backendCancel()
		b, err := smolmailer.NewBackend(backendCtx, logger.With("component", "backend"), q, cfg)
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

		sender, err := smolmailer.NewSender(ctxSender, logger.With("component", "sender"), cfg, q)
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
