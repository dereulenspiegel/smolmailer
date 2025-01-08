package smolmailer

import (
	"context"

	"github.com/joncrlsn/dque"
)

type senderQueue interface {
	Receive() (*QueuedMessage, error)
}

type smtpForwarder interface {
	Send(*Session) error
}

type Sender struct {
	q senderQueue

	ctx       context.Context
	ctxCancel context.CancelFunc
}

func NewSender(ctx context.Context, q senderQueue) (*Sender, error) {
	bCtx, cancel := context.WithCancel(ctx)
	s := &Sender{
		ctx:       bCtx,
		ctxCancel: cancel,
		q:         q,
	}
	go s.run()
	return s, nil
}

func (s *Sender) Close() error {
	s.ctxCancel()
	return nil
}

func (s *Sender) run() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			msg, err := s.q.Receive()
			if err == dque.ErrEmpty {
				continue
			}
			go s.trySend(msg)
		}
	}
}

func (s *Sender) trySend(msg *QueuedMessage) {

}
