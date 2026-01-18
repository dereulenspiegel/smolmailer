package queue

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/khepin/liteq"
	_ "github.com/mattn/go-sqlite3"
)

type GenericWorkQueue[T any] interface {
	Queue(ctx context.Context, item T, options ...liteq.QueueOption) error
	Consume(ctx context.Context, worker liteq.ConsumeFunc[T], options ...liteq.ConsumeOpt) error
}

type SQLiteWorkQueue[T any] = liteq.Queue[T]

func NewSQLiteWorkQueueOnDb[T any](db *sql.DB, queueName string, poolSize, timeout int) (*SQLiteWorkQueue[T], error) {
	jq, err := liteq.New(db)
	if err != nil {
		return nil, fmt.Errorf("failed to setup job queue: %w", err)
	}
	q := liteq.NewQueue(jq, queueName, liteq.JSONMarshaler[T]{})
	return q, nil
}

func NewSQLiteWorkQueue[T any](path, queueName string, poolSize, timeout int) (*SQLiteWorkQueue[T], error) {
	liteDb, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open queue db: %w", err)
	}
	return NewSQLiteWorkQueueOnDb[T](liteDb, queueName, poolSize, timeout)
}
