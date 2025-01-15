//go:generate go run github.com/vektra/mockery/v2

package smolmailer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
)

type backendQueue interface {
	QueueMessage(msg *QueuedMessage) error
}

type userService interface {
	Authenticate(username, password string) error
	IsValidSender(username, from string) bool
}

type Backend struct {
	q   backendQueue
	cfg *Config

	allowedIPNets []*net.IPNet

	passwdDecoder *crypt.Decoder
}

func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	remoteAddr := conn.Conn().RemoteAddr()
	if !b.isValidRemoteAddr(remoteAddr) {
		return nil, fmt.Errorf("the client %s is not allowed to send messages", remoteAddr.String())
	}
	return NewSession(b.q, b), nil
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

func NewBackend(q backendQueue, cfg *Config) (*Backend, error) {
	b := &Backend{
		q:   q,
		cfg: cfg,
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

	q       backendQueue
	userSrv userService
}

func NewSession(q backendQueue, userSrv userService) *Session {
	return &Session{
		Msg:     &ReceivedMessage{},
		userSrv: userSrv,
		q:       q,
	}
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.Msg.From = from
	if s.authenticatedSubject == "" {
		return fmt.Errorf("not authenticated")
	}

	if !s.userSrv.IsValidSender(s.authenticatedSubject, s.Msg.From) {
		return fmt.Errorf("user %s is now allowed to send emails as %s", s.authenticatedSubject, s.Msg.From)
	}
	if opts != nil {
		s.ExpectedBodySize = opts.Size
	}
	s.Msg.MailOpts = opts
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.Msg.To = append(s.Msg.To, &Rcpt{
		To:       to,
		RcptOpts: opts,
	})
	return nil
}

func (s *Session) Data(r io.Reader) (err error) {

	lr := r
	if s.ExpectedBodySize > 0 {
		lr = io.LimitReader(r, s.ExpectedBodySize)
	}
	s.Msg.Body, err = io.ReadAll(lr)
	n := len(s.Msg.Body)
	if s.ExpectedBodySize > 0 && int64(n) != s.ExpectedBodySize {
		return fmt.Errorf("read only %d body bytes, but expected %d bytes", n, s.ExpectedBodySize)
	}
	if err != nil {
		return fmt.Errorf("failed to read message body: %w", err)
	}

	for _, msg := range s.Msg.QueuedMessages() {
		if err := s.q.QueueMessage(msg); err != nil {
			return fmt.Errorf("failed to queue message: %w", err)
		}
	}

	return nil
}

func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *Session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if identity != "" && identity != username {
			return errors.New("invalid identity")
		}
		if err := s.userSrv.Authenticate(username, password); err != nil {
			return fmt.Errorf("failed to authenticate user %s: %w", username, err)
		}
		s.authenticatedSubject = username
		return nil
	}), nil
}

func (s *Session) Reset() {
	s.Msg = &ReceivedMessage{}
}

func (s *Session) Logout() error {
	return nil
}

func pbkdf2OnlyDecoder() (decoder *crypt.Decoder, err error) {
	decoder = crypt.NewDecoder()
	if err := pbkdf2.RegisterDecoderSHA512(decoder); err != nil {
		return nil, err
	}
	return decoder, nil
}

func pbkdf2OnlyHasher() (algorithm.Hash, error) {
	return pbkdf2.NewSHA512()
}

func encodePassword(password string, hasher algorithm.Hash) (string, error) {
	hash, err := hasher.Hash(password)
	if err != nil {
		return "", err
	}
	return algorithm.Digest.Encode(hash), nil
}
