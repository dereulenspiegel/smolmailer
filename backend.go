package smolmailer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/internal/config"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type userService interface {
	Authenticate(username, password string) error
	IsValidSender(username, from string) bool
}

type Backend struct {
	q       GenericWorkQueue[*ReceivedMessage]
	cfg     *config.Config
	logger  *slog.Logger
	ctx     context.Context
	userSrv userService

	allowedIPNets []*net.IPNet
}

func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	remoteAddr := conn.Conn().RemoteAddr()
	if !b.isValidRemoteAddr(remoteAddr) {
		return nil, fmt.Errorf("the client %s is not allowed to send messages", remoteAddr.String())
	}
	return NewSession(b.ctx, b.logger.With("session", true, "remoteAddr", conn.Conn().RemoteAddr().String()), b.q, b.userSrv, conn.Conn().RemoteAddr()), nil
}

func (b *Backend) isValidRemoteAddr(remoteAddr net.Addr) bool {
	if len(b.allowedIPNets) == 0 {
		return true
	}
	addPrt, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil {
		return false
	}
	rmtAddr := net.IP(addPrt.Addr().AsSlice())
	for _, ipNet := range b.allowedIPNets {
		if ipNet.Contains(rmtAddr) {
			return true
		}
	}
	return false
}

func NewBackend(ctx context.Context, logger *slog.Logger, q GenericWorkQueue[*ReceivedMessage], userSrv userService, cfg *config.Config) (*Backend, error) {
	b := &Backend{
		q:       q,
		cfg:     cfg,
		logger:  logger,
		ctx:     ctx,
		userSrv: userSrv,
	}
	for _, netString := range cfg.AllowedIPRanges {
		_, ipNet, err := net.ParseCIDR(netString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR %s: %w", netString, err)
		}
		b.allowedIPNets = append(b.allowedIPNets, ipNet)
	}

	return b, nil
}

type Rcpt struct {
	To       string
	RcptOpts *smtp.RcptOptions
}

func (r *Rcpt) String() string {
	return r.To
}

type ReceivedMessage struct {
	From     string
	To       []*Rcpt
	Body     []byte
	MailOpts *smtp.MailOptions
}

func (m *ReceivedMessage) LogValue() slog.Value {
	envelopeID := "na"
	if m.MailOpts != nil {
		envelopeID = m.MailOpts.EnvelopeID
	}
	recipients := make([]string, len(m.To))
	for i, to := range m.To {
		recipients[i] = to.String()
	}
	return slog.GroupValue(
		slog.String("from", m.From),
		slog.String("envelopeId", envelopeID),
		slog.String("recipients", strings.Join(recipients, ",")),
	)
}

func (r *ReceivedMessage) QueuedMessages() (msgs []*QueuedMessage) {
	receivedAt := time.Now()
	for _, to := range r.To {
		msgs = append(msgs, &QueuedMessage{
			From:       r.From,
			To:         to.To,
			RcptOpt:    to.RcptOpts,
			MailOpts:   r.MailOpts,
			Body:       r.Body,
			ReceivedAt: receivedAt,
			ErrorCount: 0,
		})
	}
	return msgs
}

type QueuedMessage struct {
	From string
	To   string
	Body []byte

	MailOpts *smtp.MailOptions
	RcptOpt  *smtp.RcptOptions

	ReceivedAt          time.Time
	LastDeliveryAttempt time.Time
	ErrorCount          int
	LastErr             error
}

func (m *QueuedMessage) LogValue() slog.Value {
	envelopeID := "na"
	if m.MailOpts != nil {
		envelopeID = m.MailOpts.EnvelopeID
	}
	return slog.GroupValue(
		slog.String("from", m.From),
		slog.String("to", m.To),
		slog.String("envelopeId", envelopeID),
	)
}

type Session struct {
	Msg              *ReceivedMessage
	ExpectedBodySize int64

	authenticatedSubject string

	plainAuthServer sasl.Server
	loginAuthServer sasl.Server

	q          GenericWorkQueue[*ReceivedMessage]
	userSrv    userService
	logger     *slog.Logger
	ctx        context.Context
	logVals    []slog.Attr
	remoteAddr net.Addr
}

func NewSession(ctx context.Context, logger *slog.Logger, q GenericWorkQueue[*ReceivedMessage], userSrv userService, remoteAddr net.Addr) *Session {
	logger.Info("Starting new session")
	s := &Session{
		Msg:        &ReceivedMessage{},
		userSrv:    userSrv,
		q:          q,
		logger:     logger,
		ctx:        ctx,
		remoteAddr: remoteAddr,
		logVals:    []slog.Attr{slog.String("remoteAddr", remoteAddr.String())},
	}

	s.plainAuthServer = sasl.NewPlainServer(func(identity, username, password string) error {
		logger := logger.With(slog.String("username", username), slog.String("identity", identity))
		logger.Debug("authenticating user")
		if identity != "" && identity != username {
			logger.Error("invalid identity")
			return errors.New("invalid identity")
		}
		if err := s.userSrv.Authenticate(username, password); err != nil {
			logger.Error("failed to authenticate user", "err", err)
			return fmt.Errorf("failed to authenticate user %s: %w", username, err)
		}
		logger.Info("user authenticated successfully")
		s.authenticatedSubject = username
		return nil
	})

	s.loginAuthServer = NewLoginServer(func(username, password string) error {
		logger := logger.With(slog.String("username", username))
		logger.Debug("authenticating user")
		if err := s.userSrv.Authenticate(username, password); err != nil {
			logger.Error("failed to authenticate user", "err", err)
			return err
		}
		logger.Info("user authenticated successfully")
		s.authenticatedSubject = username
		return nil
	})

	return s
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	logger := s.logWithGroup("Mail", slog.String("from", from), slog.String("envelopeId", opts.EnvelopeID), slog.Bool("requireTLS", opts.RequireTLS))
	logger.Info("Mail from")
	if s.authenticatedSubject == "" {
		logger.Warn("declining unauthenticated session")
		return fmt.Errorf("not authenticated")
	}
	if !s.userSrv.IsValidSender(s.authenticatedSubject, from) {
		logger.Warn("not a valid sender")
		return fmt.Errorf("user %s is not allowed to send emails as %s", s.authenticatedSubject, s.Msg.From)
	}
	s.Msg.From = from
	if opts != nil {
		s.ExpectedBodySize = opts.Size
	}
	s.Msg.MailOpts = opts
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	logger := s.logWithGroup("Rcpt", slog.String("to", to))
	logger.Info("Rcpt to")
	s.Msg.To = append(s.Msg.To, &Rcpt{
		To:       to,
		RcptOpts: opts,
	})
	return nil
}

const defaultRetryAttempts = 3

func (s *Session) Data(r io.Reader) (err error) {
	logger := s.logWithGroup("Data", slog.Int64("expectedBodySize", s.ExpectedBodySize))
	logger.Info("Receiving data")
	lr := r
	if s.ExpectedBodySize > 0 {
		lr = io.LimitReader(r, s.ExpectedBodySize)
	}
	s.Msg.Body, err = io.ReadAll(lr)
	n := len(s.Msg.Body)
	if s.ExpectedBodySize > 0 && int64(n) != s.ExpectedBodySize {
		logger.Error("Invalid body size", slog.Int("bodySize", n))
		return fmt.Errorf("read only %d body bytes, but expected %d bytes", n, s.ExpectedBodySize)
	}
	if err != nil {
		logger.Error("failed to read message body", "err", err)
		return fmt.Errorf("failed to read message body: %w", err)
	}
	if err := s.q.Queue(s.ctx, s.Msg, QueueWithAttempts(defaultRetryAttempts)); err != nil {
		logger.Error("failed to queue received message", "err", err)
		return fmt.Errorf("failed to queue received msg: %w", err)
	}

	return nil
}

func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *Session) Auth(mech string) (sasl.Server, error) {
	logger := s.logWithGroup("Auth", slog.String("authMech", mech))

	switch mech {
	case sasl.Plain:
		return s.plainAuthServer, nil
	case sasl.Login:
		return s.loginAuthServer, nil
	default:
		logger.Error("unsupported auth method")
		return nil, fmt.Errorf("unsupported auth method %s", mech)
	}
}

func (s *Session) Reset() {
	logger := s.logWithGroup("Reset")
	logger.Debug("session reset")
	s.Msg = &ReceivedMessage{}
	s.logVals = []slog.Attr{}
}

func (s *Session) Logout() error {
	logger := s.logWithGroup("Logout")
	logger.Debug("logging user out")
	return nil
}

func (s *Session) logWithGroup(stage string, additionalGroupVals ...slog.Attr) *slog.Logger {
	s.logVals = append(s.logVals, additionalGroupVals...)
	s.logVals = append(s.logVals, slog.Any("msg", s.Msg))
	return s.logger.With(slog.Any("session", s), slog.String("stage", stage))
}

func (s *Session) LogValue() slog.Value {
	if len(s.logVals) == 0 {
		// Seems having 0 log vals causes a nil logger later on
		s.logVals = append(s.logVals, slog.String("remoteAddr", s.remoteAddr.String()))
	}
	return slog.GroupValue(s.logVals...)
}
