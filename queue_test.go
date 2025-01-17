package smolmailer

import (
	"testing"

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
