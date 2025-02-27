package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dereulenspiegel/smolmailer/internal/config"
	"github.com/dereulenspiegel/smolmailer/internal/server"
	"github.com/spf13/viper"

	_ "github.com/mattn/go-sqlite3"
)

var (
	logLevel = new(slog.LevelVar)
)

func main() {
	ctx := context.Background()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var srv *server.Server
	var err error

	go func() {
		config.ConfigDefaults()
		if err := viper.ReadInConfig(); err != nil && !errors.Is(err, &viper.ConfigFileNotFoundError{}) {
			logger.Warn("failed to read config", "err", err)
		}
		cfg := &config.Config{}
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

		srv, err = server.NewServer(ctx, logger, cfg)
		if err != nil {
			logger.Error("failed to create server", "err", err)
			os.Exit(13)
		}
		if err := srv.Serve(); err != nil {
			logger.Error("failed to serve", "err", err)
			os.Exit(1)
		}
	}()

	<-sigs
	logger.Info("shutting down")
	if err := srv.Shutdown(); err != nil {
		logger.Error("error during shutdown", "err", err)
	}
	logger.Info("shutdown")
}
