package sender

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/dereulenspiegel/liteq"
	"github.com/dereulenspiegel/smolmailer/internal/backend"
	"github.com/dereulenspiegel/smolmailer/internal/queue"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

type ReceiveProcessor func(*backend.ReceivedMessage) (*backend.ReceivedMessage, error)
type PreSendProcessor func(*queue.QueuedMessage) (*queue.QueuedMessage, error)

type JobQueue[M any] interface {
	Put(context.Context, M, ...liteq.QueueOption) error
	Consume(context.Context, liteq.ConsumeFunc[M], ...liteq.ConsumeOpt) error
}

type PreprocessorHandler struct {
	receivingQueue queue.GenericWorkQueue[*backend.ReceivedMessage]

	receiveProcessors []ReceiveProcessor
	preprocessors     []PreSendProcessor

	logger *slog.Logger
}

type ProcessingOpt func(*PreprocessorHandler)

func WithReceiveProcessors(receiveProcessors ...ReceiveProcessor) ProcessingOpt {
	return func(p *PreprocessorHandler) {
		p.receiveProcessors = append(p.receiveProcessors, receiveProcessors...)
	}
}

func WithPreSendProcessors(preSendProcessors ...PreSendProcessor) ProcessingOpt {
	return func(p *PreprocessorHandler) {
		p.preprocessors = append(p.preprocessors, preSendProcessors...)
	}
}

func NewProcessorHandler(ctx context.Context,
	logger *slog.Logger,
	receivingQueue queue.GenericWorkQueue[*backend.ReceivedMessage], opts ...ProcessingOpt) (*PreprocessorHandler, error) {

	p := &PreprocessorHandler{
		receivingQueue:    receivingQueue,
		receiveProcessors: make([]ReceiveProcessor, 0),
		preprocessors:     make([]PreSendProcessor, 0),
		logger:            logger,
	}

	for _, opt := range opts {
		opt(p)
	}

	go p.runConsumeReceivingQueue(ctx)

	return p, nil
}

func (p *PreprocessorHandler) runConsumeReceivingQueue(ctx context.Context) {
	if err := p.receivingQueue.Consume(ctx, p.consumeReceivingQueue); err != nil {
		p.logger.Error("failed to consume from receiving queue", "err", err)
	}
}

func (p *PreprocessorHandler) consumeReceivingQueue(ctx context.Context, receivedMsg *backend.ReceivedMessage) (err error) {
	if receivedMsg.MailOpts == nil {
		receivedMsg.MailOpts = &smtp.MailOptions{}
	}
	logger := p.logger.With(slog.Any("receivedMsg", receivedMsg))
	logger.Info("processing received message")
	for _, receiveProcessor := range p.receiveProcessors {
		receivedMsg, err = receiveProcessor(receivedMsg)
		if err != nil {
			logger.Error("failed to process received message", "err", err, "processor", fmt.Sprintf("%T", receiveProcessor))
			return fmt.Errorf("failed to process received message: %w", err)
		}
	}

	queuedMsgs, err := p.processReceivedMessage(receivedMsg)
	if err != nil {
		logger.Error("failed to transform received message into queued message", "err", err)
		return fmt.Errorf("failed to transform received into queued message: %w", err)
	}

	for _, queuedMsg := range queuedMsgs {
		logger := logger.With(slog.String("to", queuedMsg.To))
		for _, pr := range p.preprocessors {
			queuedMsg, err = pr(queuedMsg)
			if err != nil {
				logger.Error("failed to process queued message", "err", err, "processor", fmt.Sprintf("%T", pr))
				return fmt.Errorf("failed to process queued msg: %w", err)
			}
		}
	}

	return nil
}

func (p *PreprocessorHandler) processReceivedMessage(receivedMsg *backend.ReceivedMessage) (queuedMsgs []*queue.QueuedMessage, err error) {
	queuedMsgs = receivedMsg.QueuedMessages()
	return queuedMsgs, nil
}

func SendProcessor(ctx context.Context, sendingQueue queue.GenericWorkQueue[*queue.QueuedMessage], options ...liteq.QueueOption) PreSendProcessor {
	return func(msg *queue.QueuedMessage) (*queue.QueuedMessage, error) {
		err := sendingQueue.Queue(ctx, msg, options...)
		return msg, err
	}
}

func DkimProcessor(dkimOptions *dkim.SignOptions) ReceiveProcessor {
	return func(msg *backend.ReceivedMessage) (*backend.ReceivedMessage, error) {
		signedBuf := &bytes.Buffer{}
		if err := dkim.Sign(signedBuf, bytes.NewReader(msg.Body), dkimOptions); err != nil {
			return msg, fmt.Errorf("failed to sign messag: %w", err)
		}
		msg.Body = signedBuf.Bytes()
		return msg, nil
	}
}
