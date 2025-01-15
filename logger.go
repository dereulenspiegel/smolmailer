package smolmailer

import (
	"context"
	"fmt"
	"log/slog"
)

type SlogSmtpLogger struct {
	level  slog.Level
	logger *slog.Logger
	ctx    context.Context
}

func NewSlogLogger(ctx context.Context, logger *slog.Logger, level slog.Level) *SlogSmtpLogger {
	return &SlogSmtpLogger{
		logger: logger,
		level:  level,
		ctx:    ctx,
	}
}

func (s *SlogSmtpLogger) Printf(format string, v ...interface{}) {
	s.logger.Log(s.ctx, s.level, fmt.Sprintf(format, v...))
}
func (s *SlogSmtpLogger) Println(v ...interface{}) {
	s.logger.Log(s.ctx, s.level, fmt.Sprintln(v...))
}
