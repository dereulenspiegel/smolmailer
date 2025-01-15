package smolmailer

import (
	"context"
	"log"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/joncrlsn/dque"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/inbucket"
)

func TestDeliverMail(t *testing.T) {
	ctx := context.Background()
	qDir := t.TempDir()

	msg := &QueuedMessage{
		From:       "someone@sub.example.com",
		To:         "else@example.com",
		Body:       []byte("test"),
		ReceivedAt: time.Now(),
	}

	sq := newSenderQueueMock(t)
	sq.On("Receive").Return(func() (*QueuedMessage, error) {
		time.Sleep(100)
		return nil, dque.ErrEmpty
	})

	sender, err := NewSender(ctx, slog.With("component", "sender"), &Config{
		Domain:    "example.com",
		QueuePath: qDir,
		Dkim: &DkimOpts{
			Selector: "smolmailer",
			PrivateKey: `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhGWXSKnABUEcPSYV00xfxhR6sf/3iEsJfrOxE3H/3r
-----END PRIVATE KEY-----
			`,
		},
	}, sq)
	require.NoError(t, err)
	defer sender.Close()

	smtpContainer, err := inbucket.Run(ctx, "inbucket/inbucket")
	require.NoError(t, err)
	defer func() {
		if err := testcontainers.TerminateContainer(smtpContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()

	sender.mxResolver = func(domain string) ([]*net.MX, error) {
		containerPort, err := smtpContainer.MappedPort(ctx, "2500/tcp")
		sender.mxPorts = []int{containerPort.Int()}
		require.NoError(t, err)
		host, err := smtpContainer.Host(ctx)
		require.NoError(t, err)

		mxRecord := &net.MX{
			Host: host,
			Pref: 10,
		}
		return []*net.MX{mxRecord}, nil
	}

	err = sender.sendMail(msg)
	require.NoError(t, err)
}
