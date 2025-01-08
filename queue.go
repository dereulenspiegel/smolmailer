package smolmailer

import (
	"fmt"

	"github.com/joncrlsn/dque"
)

const mailQeueuName = "mail-queue"
const segmentSize = 50

type DQeue struct {
	q *dque.DQue
}

func SessionBuilder() interface{} {
	return &QueuedMessage{}
}

func NewDQeue(cfg *Config) (*DQeue, error) {
	q, err := dque.NewOrOpen(mailQeueuName, cfg.QueuePath, segmentSize, SessionBuilder)
	if err != nil {
		return nil, fmt.Errorf("failed to create or open persistent queue:%w", err)
	}
	return &DQeue{
		q: q,
	}, nil
}

func (d *DQeue) QueueMessage(msg *QueuedMessage) error {
	return d.q.Enqueue(msg)
}

func (d *DQeue) Close() error {
	return d.q.Close()
}
