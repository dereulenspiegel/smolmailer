package server

import (
	"context"
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

	dkimed25519Key := `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPP6YdTb47JgAPxNhxtZTK1LAGs61eJYNa1S0S7G9Cv1
-----END PRIVATE KEY-----
	`

	dkimRsaKey := `
-----BEGIN PRIVATE KEY-----
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
47P6nylmO1mYdcK77VvqihsaYYxM1A==
-----END PRIVATE KEY-----
	`

	containerPort, err := smtpContainer.MappedPort(ctx, "2500/tcp")
	require.NoError(t, err)

	logger := slog.Default()
	cfg := &config.Config{
		MailDomain: "auth.example.com",
		ListenAddr: ":2525",
		ListenTls:  false,
		LogLevel:   "DEBUG",
		QueuePath:  filepath.Join(t.TempDir(), "queues"),
		UserFile:   userFilePath,
		Dkim: &config.DkimOpts{
			Signer: map[string]*config.DkimSigner{
				"ed25519": &config.DkimSigner{
					Selector:   "smolmailer-ed25519",
					PrivateKey: &config.PrivateKey{Value: dkimed25519Key},
				},
				"rsa": &config.DkimSigner{
					Selector:   "smolmailer-rsa",
					PrivateKey: &config.PrivateKey{Value: dkimRsaKey},
				},
			},
		},
		TestingOpts: &config.TestingOpts{
			MxPorts: []int{containerPort.Int()},
			MxResolv: func(domain string) ([]*net.MX, error) {
				host, err := smtpContainer.Host(ctx)
				require.NoError(t, err)

				mxRecord := &net.MX{
					Host: host,
					Pref: 10,
				}
				return []*net.MX{mxRecord}, nil
			},
		},
	}

	server, err := NewServer(ctx, logger, cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

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
