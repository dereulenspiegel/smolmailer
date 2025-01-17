package smolmailer

import (
	"github.com/joncrlsn/dque"
)

type GenericQueue[T any] interface {
	Send(item T) error
	Receive() (item T, err error)
	Close() error
}

type GenericPersistentQueue[T any] struct {
	dq *dque.DQue
}

var ErrQueueEmpty = newQueueError("queue empty")

type QueueError struct {
	message string
	cause   error
}

func (q *QueueError) Error() string {
	return q.message
}

func (q *QueueError) Unwrap() error {
	return q.cause
}

func newQueueError(message string) *QueueError {
	return &QueueError{message: message}
}

func newQueueErrorWithCause(message string, cause error) *QueueError {
	return &QueueError{
		message: message,
		cause:   cause,
	}
}

func NewGenericPersistentQueue[T any](name, dir string, segmentSize int) (*GenericPersistentQueue[T], error) {
	dq, err := dque.NewOrOpen(name, dir, segmentSize, func() interface{} {
		return new(T)
	})
	if err != nil {
		return nil, newQueueErrorWithCause("failed to create persistent internal queue", err)
	}
	return &GenericPersistentQueue[T]{
		dq: dq,
	}, nil
}

func (g *GenericPersistentQueue[T]) Send(item T) error {
	if err := g.dq.Enqueue(item); err != nil {
		return newQueueErrorWithCause("failed to enqueue item", err)
	}
	return nil
}

func (g *GenericPersistentQueue[T]) Receive() (item T, err error) {
	i, err := g.dq.Dequeue()
	if err != nil {
		if err == dque.ErrEmpty {
			return item, ErrQueueEmpty
		}
		return item, newQueueErrorWithCause("failed to read from internal queue", err)
	}
	return i.(T), err
}

func (g *GenericPersistentQueue[T]) Close() error {
	if err := g.dq.Close(); err != nil {
		return newQueueErrorWithCause("failed to close internal queue", err)
	}
	return nil
}
