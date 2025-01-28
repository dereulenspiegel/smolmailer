package smolmailer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/khepin/liteq"
)

type QueueError struct {
	message string
	cause   error
}

func (q *QueueError) Error() string {
	if q.cause != nil {
		return fmt.Sprintf("%s. caused by: %s", q.message, q.cause.Error())
	}
	return q.message
}

func (q *QueueError) Unwrap() error {
	return q.cause
}

func newQueueErrorWithCause(message string, cause error) *QueueError {
	return &QueueError{
		message: message,
		cause:   cause,
	}
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

func NewSQLiteWorkQueueOnDb[T any](db *sql.DB, queueName string, poolSize, timeout int) (*SQLiteWorkQueue[T], error) {
	if err := liteq.Setup(db); err != nil {
		return nil, newQueueErrorWithCause("failed to setup sqlte db", err)
	}
	q := liteq.New(db)
	sq := &SQLiteWorkQueue[T]{
		squeue:    q,
		queueName: queueName,
		poolSize:  poolSize,
		timeout:   timeout,
	}
	return sq, nil
}

func NewSQLiteWorkQueue[T any](path, queueName string, poolSize, timeout int) (*SQLiteWorkQueue[T], error) {
	liteDb, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, newQueueErrorWithCause("failed to open sqliteddb", err)
	}
	return NewSQLiteWorkQueueOnDb[T](liteDb, queueName, poolSize, timeout)
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
