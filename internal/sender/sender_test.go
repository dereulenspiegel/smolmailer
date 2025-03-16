package sender

import (
	"context"
	"encoding/base64"
	"log"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/dereulenspiegel/smolmailer/internal/config"
	"github.com/dereulenspiegel/smolmailer/internal/queue"
	"github.com/docker/go-connections/nat"
	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/inbucket"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestDeliverMail(t *testing.T) {
	ctx := context.Background()
	qDir := t.TempDir()

	msg := &queue.QueuedMessage{
		From:       "someone@sub.example.com",
		To:         "else@example.com",
		Body:       []byte("test"),
		ReceivedAt: time.Now(),
		MailOpts:   &smtp.MailOptions{},
	}

	sq, err := queue.NewSQLiteWorkQueue[*queue.QueuedMessage](filepath.Join(t.TempDir(), "queue.db"), "send.queue", 1, 300)
	require.NoError(t, err)

	sender, err := NewSender(ctx, slog.With("component", "sender"), &config.Config{
		MailDomain: "example.com",
		QueuePath:  qDir,
		Dkim: &config.DkimOpts{
			Selector: "smolmailer",
			PrivateKeys: &config.DkimPrivateKeys{
				Ed25519: base64.StdEncoding.EncodeToString([]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhGWXSKnABUEcPSYV00xfxhR6sf/3iEsJfrOxE3H/3r
-----END PRIVATE KEY-----
			`)),
			},
		},
	}, sq)
	require.NoError(t, err)
	defer sender.Close()

	mxPort, err := nat.NewPort("tcp", "2500")
	require.NoError(t, err)
	smtpContainer, err := inbucket.Run(ctx, "inbucket/inbucket", testcontainers.WithWaitStrategy(wait.NewHostPortStrategy(mxPort)))
	require.NoError(t, err)
	defer func() {
		if err := testcontainers.TerminateContainer(smtpContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()

	sender.mxResolver = func(domain string) ([]*net.MX, error) {
		containerPort, err := smtpContainer.MappedPort(ctx, mxPort)
		require.NoError(t, err)
		sender.mxPorts = []int{containerPort.Int()}
		host, err := smtpContainer.Host(ctx)
		require.NoError(t, err)

		mxRecord := &net.MX{
			Host: host,
			Pref: 10,
		}
		return []*net.MX{mxRecord}, nil
	}

	err = sq.Queue(context.Background(), msg)
	require.NoError(t, err)
}
