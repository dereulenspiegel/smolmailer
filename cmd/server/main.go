package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dereulenspiegel/smolmailer"
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
		if err := viper.ReadInConfig(); err != nil {
			logger.Error("failed to read config", "err", err)
			panic(err)
		}
		cfg := &smolmailer.Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			logger.Error("failed to unmarshal config", "err", err)
			panic(err)
		}

		q, err := smolmailer.NewDQeue(cfg)
		if err != nil {
			logger.Error("failed to create queue", "err", err)
			panic(err)
		}

		b, err := smolmailer.NewBackend(q, cfg)
		if err != nil {
			logger.Error("failed to create backend", "err", err)
			panic(err)
		}

		s := smtp.NewServer(b)
		s.Domain = cfg.Domain
		s.WriteTimeout = 10 * time.Second
		s.ReadTimeout = 10 * time.Second
		s.MaxMessageBytes = 1024 * 1024
		s.MaxRecipients = 1
		s.AllowInsecureAuth = false

		sender, err := smolmailer.NewSender(ctxSender, logger.With("component", "sender"), cfg, q)
		if err != nil {
			logger.Error("failed to create sender", "err", err)
			panic(err)
		}

		// TODO set TLS config s.TLSConfig

		if err := s.ListenAndServeTLS(); err != nil {
			logger.Error("failed to listen on addr", "err", err, "addr", cfg.ListenAddr)
		}
		sender.Close()
	}()

	<-sigs
	logger.Info("shutting down")
}
