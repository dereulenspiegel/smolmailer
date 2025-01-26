package smolmailer

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestValidateIPRange(t *testing.T) {
	_, v4Net, err := net.ParseCIDR("172.7.0.0/24")
	require.NoError(t, err)
	_, v6Net, err := net.ParseCIDR("fd38:0d92:4cd6::/48")
	require.NoError(t, err)
	b := &Backend{
		allowedIPNets: []*net.IPNet{
			v4Net,
			v6Net,
		},
	}

	for _, exp := range []struct {
		addrStr string
		valid   bool
	}{
		{
			addrStr: "172.7.0.12:50551",
			valid:   true,
		},
		{
			addrStr: "172.7.1.12:1234",
			valid:   false,
		},
		{
			addrStr: "[fd38:0d92:4cd6::1]:1234",
			valid:   true,
		},
		{
			addrStr: "[2a01:a700:4404:3:443b:1827:877d:cfeb]:1234",
			valid:   false,
		},
	} {
		remoteAddr, err := net.ResolveTCPAddr("tcp", exp.addrStr)
		require.NoError(t, err)
		assert.Equal(t, exp.valid, b.isValidRemoteAddr(remoteAddr))
	}

}

func TestSessionQueuesSuccessfully(t *testing.T) {
	ctx := context.Background()
	q := NewGenericWorkQueueMock[*ReceivedMessage](t)
	usrSrv := newUserServiceMock(t)

	usrSrv.On("IsValidSender", "validUser", "valid@example.com").Return(true)

	sess := NewSession(ctx, slog.Default(), q, usrSrv)

	q.On("Queue", mock.AnythingOfType("context.backgroundCtx"), mock.MatchedBy(func(msg *ReceivedMessage) bool {
		return msg.From == "valid@example.com" && msg.To[0].To == "valid@example.com" && string(msg.Body) == "test"
	}), mock.AnythingOfType("smolmailer.queueOption")).Return(nil)

	sess.authenticatedSubject = "validUser" // Pretend we went through authentication
	require.NoError(t, sess.Mail("valid@example.com", &smtp.MailOptions{}))
	require.NoError(t, sess.Rcpt("valid@example.com", &smtp.RcptOptions{}))
	require.NoError(t, sess.Data(bytes.NewBufferString("test")))
}
