//go:generate go run github.com/vektra/mockery/v2

package smolmailer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
)

type queue interface {
	QueueSession(s *Session) error
}

type userService interface {
	Authenticate(username, password string) error
	IsValidSender(username, from string) bool
}

type Backend struct {
	q   queue
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

func NewBackend(q queue, cfg *Config) (*Backend, error) {
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

type Session struct {
	From             string
	To               []string
	ExpectedBodySize int64
	BodyData         *bytes.Buffer

	authenticatedSubject string

	q       queue
	userSrv userService
}

func NewSession(q queue, userSrv userService) *Session {
	return &Session{
		BodyData: &bytes.Buffer{},
		userSrv:  userSrv,
		q:        q,
	}
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.From = from // TODO verify from address
	if opts != nil {
		s.ExpectedBodySize = opts.Size
	}
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.To = append(s.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if !s.userSrv.IsValidSender(s.authenticatedSubject, s.From) {
		return fmt.Errorf("user %s is now allowed to send emails as %s", s.authenticatedSubject, s.From)
	}

	lr := r
	if s.ExpectedBodySize > 0 {
		lr = io.LimitReader(r, s.ExpectedBodySize)
	}
	n, err := s.BodyData.ReadFrom(lr)
	if s.ExpectedBodySize > 0 && n != s.ExpectedBodySize {
		return fmt.Errorf("read only %d body bytes, but expected %d bytes", n, s.ExpectedBodySize)
	}
	if err != nil {
		return fmt.Errorf("failed to read message body: %w", err)
	}

	if err := s.q.QueueSession(s); err != nil {
		return fmt.Errorf("failed to queue message: %w", err)
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
	s.To = nil
	s.From = ""
	s.BodyData = &bytes.Buffer{}
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
