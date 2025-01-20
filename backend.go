//go:generate go run github.com/vektra/mockery/v2

package smolmailer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/go-crypt/crypt"
)

type backendQueue interface {
	QueueMessage(msg *QueuedMessage) error
}

type userService interface {
	Authenticate(username, password string) error
	IsValidSender(username, from string) bool
}

type Backend struct {
	q      GenericQueue[*QueuedMessage]
	cfg    *Config
	logger *slog.Logger
	ctx    context.Context

	allowedIPNets []*net.IPNet

	passwdDecoder *crypt.Decoder
}

func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	remoteAddr := conn.Conn().RemoteAddr()
	if !b.isValidRemoteAddr(remoteAddr) {
		return nil, fmt.Errorf("the client %s is not allowed to send messages", remoteAddr.String())
	}
	return NewSession(b.ctx, b.logger.With("session", true, "remoteAddr", conn.Conn().RemoteAddr().String()), b.q, b), nil
}

func (b *Backend) Authenticate(username, password string) error {
	user := b.findUserByUsername(username)
	if user == nil {
		return fmt.Errorf("user %s is not valid", username)
	}
	digest, err := b.passwdDecoder.Decode(user.Password)
	if err != nil {
		return fmt.Errorf("invalid password digest for user %s: %w", username, err)
	}
	if !digest.Match(password) {
		return fmt.Errorf("invalid password for user %s", username)
	}
	return nil
}

func (b *Backend) IsValidSender(username, from string) bool {
	user := b.findUserByUsername(username)
	return user != nil && user.FromAddr == from
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

func (b *Backend) findUserByUsername(username string) *UserConfig {
	for _, user := range b.cfg.Users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

func NewBackend(ctx context.Context, logger *slog.Logger, q GenericQueue[*QueuedMessage], cfg *Config) (*Backend, error) {
	b := &Backend{
		q:      q,
		cfg:    cfg,
		logger: logger,
		ctx:    ctx,
	}
	for _, netString := range cfg.AllowedIPRanges {
		_, ipNet, err := net.ParseCIDR(netString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR %s: %w", netString, err)
		}
		b.allowedIPNets = append(b.allowedIPNets, ipNet)
	}

	passwdDecoder, err := pbkdf2OnlyDecoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create password decoder: %w", err)
	}
	b.passwdDecoder = passwdDecoder

	return b, nil
}

type Rcpt struct {
	To       string
	RcptOpts *smtp.RcptOptions
}

type ReceivedMessage struct {
	From     string
	To       []*Rcpt
	Body     []byte
	MailOpts *smtp.MailOptions
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

type Session struct {
	Msg              *ReceivedMessage
	ExpectedBodySize int64

	authenticatedSubject string

	q       GenericQueue[*QueuedMessage]
	userSrv userService
	logger  *slog.Logger
	ctx     context.Context
	logVals []slog.Attr
}

func NewSession(ctx context.Context, logger *slog.Logger, q GenericQueue[*QueuedMessage], userSrv userService) *Session {
	logger.Info("Starting new session")
	return &Session{
		Msg:     &ReceivedMessage{},
		userSrv: userSrv,
		q:       q,
		logger:  logger,
		ctx:     ctx,
	}
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	logger := s.logWithGroup("Mail", slog.String("from", from), slog.String("envelopeId", opts.EnvelopeID), slog.Bool("requireTLS", opts.RequireTLS))
	logger.Info("Mail from")
	s.Msg.From = from
	if s.authenticatedSubject == "" {
		logger.Warn("declining unauthenticated session")
		return fmt.Errorf("not authenticated")
	}

	if !s.userSrv.IsValidSender(s.authenticatedSubject, s.Msg.From) {
		logger.Warn("not a valid sender")
		return fmt.Errorf("user %s is now allowed to send emails as %s", s.authenticatedSubject, s.Msg.From)
	}
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

func (s *Session) Data(r io.Reader) (err error) {
	logger := s.logWithGroup("Data", slog.Uint64("expectedBodySize", uint64(s.ExpectedBodySize)))
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

	for _, msg := range s.Msg.QueuedMessages() {
		if err := s.q.Send(msg); err != nil {
			logger.Error("failed to queue message", "err", err)
			return fmt.Errorf("failed to queue message: %w", err)
		}
	}

	return nil
}

func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *Session) Auth(mech string) (sasl.Server, error) {
	logger := s.logWithGroup("Auth", slog.String("authMech", mech))
	plainServer := sasl.NewPlainServer(func(identity, username, password string) error {
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

	loginServer := NewLoginServer(func(username, password string) error {
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

	switch mech {
	case sasl.Plain:
		return plainServer, nil
	case sasl.Login:
		return loginServer, nil
	default:
		logger.Error("unsupported auth method")
		return nil, fmt.Errorf("unsupported auth method %s", mech)
	}
}

func (s *Session) Reset() {
	logger := s.logWithGroup("Reset")
	logger.Debug("session reset")
	s.Msg = &ReceivedMessage{}
}

func (s *Session) Logout() error {
	logger := s.logWithGroup("Logout")
	logger.Debug("logging user out")
	return nil
}

func (s *Session) logWithGroup(stage string, additionalGroupVals ...slog.Attr) *slog.Logger {
	s.logVals = append(s.logVals, additionalGroupVals...)
	return s.logger.With("session", s, slog.String("stage", stage))
}

func (s *Session) LogValue() slog.Value {
	return slog.GroupValue(s.logVals...)
}
