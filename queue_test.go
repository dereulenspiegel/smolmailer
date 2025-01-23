package smolmailer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestMsgType struct {
	TestField string
}

func TestGenericQueue(t *testing.T) {
	qDir := t.TempDir()

	q, err := NewGenericPersistentQueue[*TestMsgType]("test-queue", qDir, 50)
	require.NoError(t, err)
	require.NotNil(t, q)

	msg := &TestMsgType{
		TestField: "specific msg",
	}
	err = q.Send(msg)
	require.NoError(t, err)

	rMsg, err := q.Receive()
	require.NoError(t, err)
	require.NotNil(t, rMsg)

	assert.Equal(t, "specific msg", rMsg.TestField)
}

func TestReadFromEmptyQueue(t *testing.T) {
	qDir := t.TempDir()

	q, err := NewGenericPersistentQueue[*TestMsgType]("test-queue", qDir, 50)
	require.NoError(t, err)
	require.NotNil(t, q)

	item, err := q.Receive()
	assert.ErrorIs(t, err, ErrQueueEmpty)
	assert.Empty(t, item)
}

func TestWorkerQueue(t *testing.T) {
	qPath := filepath.Join(t.TempDir(), "queue.db")
	wq, err := NewSQLiteWorkQueue[*TestMsgType](qPath, "test.queue", 1, 5)
	require.NoError(t, err)
	require.NotNil(t, wq)

	resChan := make(chan *TestMsgType, 1)
	timeOut := time.NewTimer(time.Second * 2)

	go wq.Consume(context.Background(), func(ctx context.Context, msg *TestMsgType) error {
		resChan <- msg
		return nil
	})
	require.NoError(t, err)
	err = wq.Queue(context.Background(), &TestMsgType{
		TestField: "foo",
	})
	require.NoError(t, err)

	select {
	case msg := <-resChan:
		assert.NotNil(t, msg)
		assert.Equal(t, "foo", msg.TestField)
	case <-timeOut.C:
		t.Fatal("failed to process job")
	}
}
