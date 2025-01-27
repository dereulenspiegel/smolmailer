package smolmailer

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSuccessfullPreProcessing(t *testing.T) {
	ctx := context.Background()
	rq, err := NewSQLiteWorkQueue[*ReceivedMessage](filepath.Join(t.TempDir(), "queue.db"), "send", 1, 90)
	require.NoError(t, err)

	sq := NewGenericWorkQueueMock[*QueuedMessage](t)
	sq.On("Queue", mock.Anything, mock.MatchedBy(func(msg *QueuedMessage) bool {
		return msg.From == "from@example.com"
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
	}

	err = rq.Queue(ctx, rMsg)
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 500)

	sq.AssertExpectations(t)
}
