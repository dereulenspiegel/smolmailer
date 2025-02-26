package smolmailer

import (
	"context"
	"encoding/base64"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dereulenspiegel/smolmailer/internal/config"
	inbucketClient "github.com/inbucket/inbucket/pkg/rest/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/inbucket"
	"github.com/wneessen/go-mail"
)

func TestServerIntegration(t *testing.T) {
	ctx := context.Background()
	smtpContainer, err := inbucket.Run(ctx, "inbucket/inbucket")
	require.NoError(t, err)
	defer func() {
		if err := testcontainers.TerminateContainer(smtpContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	endpoint, err := smtpContainer.WebInterface(ctx)
	require.NoError(t, err)
	inbucketClient, err := inbucketClient.New(endpoint)
	require.NoError(t, err)

	headers, err := inbucketClient.ListMailbox("user@users.example.com")
	require.NoError(t, err)
	require.Empty(t, headers)

	userYaml := []byte(`
- username: authelia
  password: $argon2id$v=19$m=2097152,t=2,p=4$SdrcJ6rSDvgFp3LIbDDZYw$O/iJ19X9KA3OZlsxx7UNy/Rr4rbubKz6sp3G6s4D3AA
  from: authelia@auth.example.com
`)
	userFilePath := filepath.Join(t.TempDir(), "users.yaml")
	err = os.WriteFile(userFilePath, userYaml, 0660)
	require.NoError(t, err)

	dkimKeyPem := `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPP6YdTb47JgAPxNhxtZTK1LAGs61eJYNa1S0S7G9Cv1
-----END PRIVATE KEY-----
	`
	dkimKey := base64.StdEncoding.EncodeToString([]byte(dkimKeyPem))

	logger := slog.Default()
	cfg := &config.Config{
		MailDomain: "auth.example.com",
		ListenAddr: ":2525",
		ListenTls:  false,
		LogLevel:   "DEBUG",
		QueuePath:  filepath.Join(t.TempDir(), "queues"),
		UserFile:   userFilePath,
		Dkim: &config.DkimOpts{
			Selector:   "smolmailer",
			PrivateKey: dkimKey,
		},
	}

	server, err := NewServer(ctx, logger, cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	server.sender.mxResolver = func(domain string) ([]*net.MX, error) {
		containerPort, err := smtpContainer.MappedPort(ctx, "2500/tcp")
		server.sender.mxPorts = []int{containerPort.Int()}
		require.NoError(t, err)
		host, err := smtpContainer.Host(ctx)
		require.NoError(t, err)

		mxRecord := &net.MX{
			Host: host,
			Pref: 10,
		}
		return []*net.MX{mxRecord}, nil
	}

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	msg := mail.NewMsg()
	err = msg.From("authelia@auth.example.com")
	require.NoError(t, err)
	err = msg.To("user@users.example.com")
	require.NoError(t, err)
	msg.Subject("Foo Subject")
	msg.SetBodyString(mail.TypeTextPlain, "Bar Body")
	c, err := mail.NewClient("127.0.0.1", mail.WithPort(2525),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername("authelia"), mail.WithPassword("foobar"),
		mail.WithTLSPolicy(mail.NoTLS))
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 100)

	err = c.DialAndSend(msg)
	require.NoError(t, err)

	timeout := time.NewTimer(time.Second * 10)
	doneChan := make(chan interface{})

	hasMail := func() bool {
		headers, err = inbucketClient.ListMailbox("user@users.example.com")
		require.NoError(t, err)
		return len(headers) > 0
	}
	go func() {
		for !hasMail() {
			time.Sleep(time.Millisecond * 100)
		}
		close(doneChan)
	}()

	select {
	case <-timeout.C:
		t.Fail()
	case <-doneChan:
	}

}
