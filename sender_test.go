package smolmailer

import (
	"context"
	"encoding/base64"
	"log"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
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
		MailOpts:   &smtp.MailOptions{},
	}

	sq, err := NewSQLiteWorkQueue[*QueuedMessage](filepath.Join(t.TempDir(), "queue.db"), "send.queue", 1, 300)
	require.NoError(t, err)

	sender, err := NewSender(ctx, slog.With("component", "sender"), &Config{
		MailDomain: "example.com",
		QueuePath:  qDir,
		Dkim: &DkimOpts{
			Selector: "smolmailer",
			PrivateKey: base64.StdEncoding.EncodeToString([]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhGWXSKnABUEcPSYV00xfxhR6sf/3iEsJfrOxE3H/3r
-----END PRIVATE KEY-----
			`)),
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

	err = sq.Queue(context.Background(), msg)
	require.NoError(t, err)
}

func TestDecodeDkimPrivateKey(t *testing.T) {
	privKeyStr := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUNCWkgwYUExYk5WaVhQSEEweEl6R1dIWDRMaWlCczcyL0sxbzZpVFdNMFgKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="

	privKey, err := ParseDkimKey(privKeyStr)
	require.NoError(t, err)
	assert.NotNil(t, privKey)
}

func TestCreateDnsRecords(t *testing.T) {
	dkimKeyPem := base64.StdEncoding.EncodeToString([]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhGWXSKnABUEcPSYV00xfxhR6sf/3iEsJfrOxE3H/3r
-----END PRIVATE KEY-----
			`))

	privateKey, err := ParseDkimKey(dkimKeyPem)
	require.NoError(t, err)

	txtVal, err := DkimTxtRecordContent(privateKey)
	require.NoError(t, err)
	assert.Equal(t, "v=DKIM1;p=MCowBQYDK2VwAyEAcg0U0fEFhhfu5KyEzQdS5WlErbZnF2YvUZIKnVSmxKg", txtVal)
}
