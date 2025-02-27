package queue

import (
	"log/slog"
	"time"

	"github.com/emersion/go-smtp"
)

type QueuedMessage struct {
	From string
	To   string
	Body []byte

	MailOpts *smtp.MailOptions
	RcptOpt  *smtp.RcptOptions

	ReceivedAt          time.Time
	LastDeliveryAttempt time.Time
	ErrorCount          int
	LastErr             error
}

func (m *QueuedMessage) LogValue() slog.Value {
	envelopeID := "na"
	if m.MailOpts != nil {
		envelopeID = m.MailOpts.EnvelopeID
	}
	return slog.GroupValue(
		slog.String("from", m.From),
		slog.String("to", m.To),
		slog.String("envelopeId", envelopeID),
	)
}
