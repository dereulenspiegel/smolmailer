package smolmailer

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSuccessfullPreProcessing(t *testing.T) {
	ctx := context.Background()
	rq, err := NewSQLiteWorkQueue[*ReceivedMessage](filepath.Join(t.TempDir(), "queue.db"), "send", 1, 90)
	require.NoError(t, err)

	timeout := time.NewTimer(time.Second * 5)
	done := make(chan interface{})

	sq := NewGenericWorkQueueMock[*QueuedMessage](t)
	sq.On("Queue", mock.Anything, mock.MatchedBy(func(msg *QueuedMessage) (ret bool) {
		defer close(done)
		ret = msg.From == "from@example.com" && msg.MailOpts.EnvelopeID == "foo-id" && msg.To == "to@example.com"
		return
	})).Once().Return(nil)

	p, err := NewProcessorHandler(ctx, slog.Default(), rq, WithPreSendProcessors(SendProcessor(ctx, sq)))
	require.NoError(t, err)
	assert.NotNil(t, p)

	rMsg := &ReceivedMessage{
		From: "from@example.com",
		To: []*Rcpt{
			{
				To: "to@example.com",
			},
		},
		Body: []byte("foobar"),
		MailOpts: &smtp.MailOptions{
			EnvelopeID: "foo-id",
		},
	}

	err = rq.Queue(ctx, rMsg)
	require.NoError(t, err)

	select {
	case <-timeout.C:
		t.Fail()
	case <-done:
	}

	sq.AssertExpectations(t)
}
