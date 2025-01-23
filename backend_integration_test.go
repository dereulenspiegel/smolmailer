package smolmailer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type serverDebugLogger struct{}

func (s *serverDebugLogger) Printf(format string, v ...interface{}) {
	fmt.Printf("[Server]"+format, v...)
}

func (s *serverDebugLogger) Println(v ...interface{}) {
	fmt.Print("[Server]")
	fmt.Println(v...)
}

func TestSendMail(t *testing.T) {
	ctx := context.Background()
	q := NewGenericWorkQueueMock[*QueuedMessage](t)
	q.On("Queue", mock.AnythingOfType("context.backgroundCtx"), mock.IsType(&QueuedMessage{}), mock.AnythingOfType("smolmailer.queueOption")).Return(nil)

	userPasswd, err := encodePassword("example", must(pbkdf2OnlyHasher()))
	require.NoError(t, err)
	cfg := &Config{
		ListenAddr: "[::1]:4465", // TODO get random port
		Domain:     "example.com",
		Users: []*UserConfig{
			{
				Username: "test",
				Password: userPasswd,
				FromAddr: "from@example.com",
			},
		},
	}
	b, err := NewBackend(ctx, slog.Default(), q, cfg)
	require.NoError(t, err)

	tcpListener, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)

	s := smtp.NewServer(b)
	s.Domain = cfg.Domain
	s.AllowInsecureAuth = true // Only for testing
	s.ErrorLog = &serverDebugLogger{}
	s.Debug = os.Stdout
	defer s.Close()
	go func() {
		if err := s.Serve(tcpListener); err != nil {
			panic(err)
		}
	}()
	time.Sleep(time.Millisecond * 1000)
	client, err := smtp.Dial(tcpListener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, client.Hello("local.example.com"))
	require.NoError(t, client.Auth(sasl.NewPlainClient("test", "test", "example")))
	require.NoError(t, client.Mail("from@example.com", &smtp.MailOptions{}))
	require.NoError(t, client.Rcpt("to@remote.example.com", &smtp.RcptOptions{}))
	writer, err := client.Data()
	require.NoError(t, err)
	writer.Write([]byte("mail body"))
	require.NoError(t, writer.Close())
	require.NoError(t, client.Quit())
}
