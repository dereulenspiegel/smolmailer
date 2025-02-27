package queue

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestMsgType struct {
	TestField string
}

func TestWorkerQueue(t *testing.T) {
	qPath := filepath.Join(t.TempDir(), "queue.db")
	wq, err := NewSQLiteWorkQueue[*TestMsgType](qPath, "test.queue", 1, 5)
	require.NoError(t, err)
	require.NotNil(t, wq)

	resChan := make(chan *TestMsgType, 1)
	timeOut := time.NewTimer(time.Second * 2)

	go func() {
		err := wq.Consume(context.Background(), func(ctx context.Context, msg *TestMsgType) error {
			resChan <- msg
			return nil
		})
		require.NoError(t, err)
	}()
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
