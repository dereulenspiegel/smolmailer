package smolmailer

import (
	"errors"
	"fmt"

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

var ErrQueueEmpty = errors.New("queue empty")

func NewGenericPersistentQueue[T any](name, dir string, segmentSize int) (*GenericPersistentQueue[T], error) {
	dq, err := dque.NewOrOpen(name, dir, segmentSize, func() interface{} {
		return new(T)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create persistent internal queue: %w", err)
	}
	return &GenericPersistentQueue[T]{
		dq: dq,
	}, nil
}

func (g *GenericPersistentQueue[T]) Send(item T) error {
	return g.dq.Enqueue(item)
}

func (g *GenericPersistentQueue[T]) Receive() (item T, err error) {
	i, err := g.dq.Dequeue()
	if err != nil {
		if err == dque.ErrEmpty {
			return item, ErrQueueEmpty
		}
		return item, err
	}
	return i.(T), err
}

func (g *GenericPersistentQueue[T]) Close() error {
	return g.dq.Close()
}
