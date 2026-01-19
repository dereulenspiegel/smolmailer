//go:build !darwin

package acme

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAcmeAccountAndObtainCertficate(t *testing.T) {
	t.Setenv("LEGO_DEBUG_ACME_HTTP_CLIENT", "1")
	ctx := context.Background()
	pebbleChallengeCtr, err := SetupPebbleChallengeServer(ctx)
	require.NoError(t, err)

	containerDns, localDns, err := pebbleChallengeCtr.DnsServerAddresses(ctx)
	require.NoError(t, err)
	pebbleCtr, err := SetupPebble(ctx, containerDns)
	require.NoError(t, err)
	require.NotNil(t, pebbleCtr)

	httpClient, err := pebbleCtr.HttpClient(ctx)
	require.NoError(t, err)
	http.DefaultClient = httpClient

	caUrl, err := pebbleCtr.AcmeUrl(ctx)
	require.NoError(t, err)

	challengeProvider, err := pebbleChallengeCtr.DNS01ChallengeProvider(ctx)
	require.NoError(t, err)

	err = dns01.AddRecursiveNameservers([]string{localDns})(nil)
	require.NoError(t, err)

	acmeDir := t.TempDir()
	a, err := NewAcme(context.Background(), slog.Default(), &Config{
		Dir:           acmeDir,
		Email:         "test@example.com",
		CAUrl:         caUrl,
		dns01Provider: challengeProvider,

		httpClient: httpClient,
		DNS01: &DNS01Config{
			DontWaitForPropagation: true,
			PropagationTimeout:     time.Second * 60,
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, a)

	err = a.ObtainCertificate("example.com")
	require.NoError(t, err)

	cert, err := a.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.PrivateKey)
}
