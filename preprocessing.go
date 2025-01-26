package smolmailer

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/emersion/go-msgauth/dkim"
)

type ReceiveProcessor func(*ReceivedMessage) (*ReceivedMessage, error)
type PreSendProcessor func(*QueuedMessage) (*QueuedMessage, error)

type PreprocessorHandler struct {
	receivingQueue GenericWorkQueue[*ReceivedMessage]

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

func SendProcessor(ctx context.Context, sendingQueue GenericWorkQueue[*QueuedMessage], options ...queueOption) PreSendProcessor {
	return func(msg *QueuedMessage) (*QueuedMessage, error) {
		err := sendingQueue.Queue(ctx, msg, options...)
		return msg, err
	}
}

func NewProcessorHandler(ctx context.Context,
	logger *slog.Logger,
	receivingQueue GenericWorkQueue[*ReceivedMessage], opts ...ProcessingOpt) (*PreprocessorHandler, error) {

	p := &PreprocessorHandler{
		receivingQueue:    receivingQueue,
		receiveProcessors: make([]ReceiveProcessor, 0),
		preprocessors:     make([]PreSendProcessor, 0),
	}

	for _, opt := range opts {
		opt(p)
	}

	go p.runConsumeReceivingQueue(ctx)

	return p, nil
}

func (p *PreprocessorHandler) runConsumeReceivingQueue(ctx context.Context) {
	p.receivingQueue.Consume(ctx, p.consumeReceivingQueue)
}

func (p *PreprocessorHandler) consumeReceivingQueue(ctx context.Context, receivedMsg *ReceivedMessage) (err error) {
	logger := p.logger.With(slog.String("from", receivedMsg.From), slog.String("envelopeId", receivedMsg.MailOpts.EnvelopeID))
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

func (p *PreprocessorHandler) processReceivedMessage(receivedMsg *ReceivedMessage) (queuedMsgs []*QueuedMessage, err error) {
	queuedMsgs = receivedMsg.QueuedMessages()
	return queuedMsgs, nil
}

func DkimProcessor(dkimOptions *dkim.SignOptions) ReceiveProcessor {
	return func(msg *ReceivedMessage) (*ReceivedMessage, error) {
		signedBuf := &bytes.Buffer{}
		if err := dkim.Sign(signedBuf, bytes.NewReader(msg.Body), dkimOptions); err != nil {
			return msg, fmt.Errorf("failed to sign messag: %w", err)
		}
		msg.Body = signedBuf.Bytes()
		return msg, nil
	}
}
