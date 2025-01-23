package smolmailer

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/joncrlsn/dque"
	"github.com/khepin/liteq"
	_ "github.com/mattn/go-sqlite3"
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

type GenericWorkQueue[T any] interface {
	Queue(ctx context.Context, item T, options ...queueOption) error
	Consume(ctx context.Context, worker func(ctx context.Context, item T) error) error
}

type queueOption func(*liteq.QueueJobParams)

func QueueWithAttempts(attempts int) queueOption {
	return func(job *liteq.QueueJobParams) {
		job.RemainingAttempts = int64(attempts)
	}
}

func QueueAfter(after time.Duration) queueOption {
	return func(job *liteq.QueueJobParams) {
		job.ExecuteAfter = int64(after.Seconds())
	}
}

func QueueWithDedupKey(key liteq.DedupingKey) queueOption {
	return func(job *liteq.QueueJobParams) {
		job.DedupingKey = key
	}
}

type SQLiteWorkQueue[T any] struct {
	squeue    *liteq.JobQueue
	queueName string
	poolSize  int
	timeout   int
}

func NewSQLiteWorkQueue[T any](path, queueName string, poolSize, timeout int) (*SQLiteWorkQueue[T], error) {
	liteDb, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, newQueueErrorWithCause("failed to open sqliteddb", err)
	}
	if err := liteq.Setup(liteDb); err != nil {
		return nil, newQueueErrorWithCause("failed to setup sqlte db", err)
	}
	q := liteq.New(liteDb)
	sq := &SQLiteWorkQueue[T]{
		squeue:    q,
		queueName: queueName,
		poolSize:  poolSize,
		timeout:   timeout,
	}
	return sq, nil
}

func (s *SQLiteWorkQueue[T]) Queue(ctx context.Context, item T, options ...queueOption) error {
	bytes, err := json.Marshal(item)
	if err != nil {
		return newQueueErrorWithCause("failed to serialize work item", err)
	}
	jobParams := liteq.QueueJobParams{
		Queue: s.queueName,
		Job:   string(bytes),
	}
	for _, opt := range options {
		opt(&jobParams)
	}
	err = s.squeue.QueueJob(ctx, jobParams)
	if err != nil {
		return newQueueErrorWithCause("failed to queue job", err)
	}
	return nil
}

func createWorker[T any](w func(context.Context, T) error) func(ctx context.Context, job *liteq.Job) error {
	return func(ctx context.Context, job *liteq.Job) error {
		var item T
		if err := json.Unmarshal([]byte(job.Job), &item); err != nil {
			return newQueueErrorWithCause("failed to deserialize job", err)
		}
		return w(ctx, item)
	}
}

func (s *SQLiteWorkQueue[T]) Consume(ctx context.Context, worker func(ctx context.Context, item T) error) error {
	err := s.squeue.Consume(ctx, liteq.ConsumeParams{
		Queue:             s.queueName,
		PoolSize:          s.poolSize,
		VisibilityTimeout: int64(s.timeout),
		Worker:            createWorker(worker),
	})
	if err != nil {
		return newQueueErrorWithCause("failed to consume from queue", err)
	}
	return nil
}
