package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsingEnvVars(t *testing.T) {
	t.Setenv("SMOLMAILER_ACME_EMAIL", "acme@example.com")
	t.Setenv("SMOLMAILER_MAILDOMAIN", "mail.example.com")
	t.Setenv("SMOLMAILER_DKIM_SIGNER_RSA_SELECTOR", "rsa-selector")
	t.Setenv("SMOLMAILER_DKIM_SIGNER_RSA_PRIVATEKEY_PATH", "/foo/rsa")
	t.Setenv("SMOLMAILER_DKIM_SIGNER_ED25519_SELECTOR", "ed25519-selector")
	t.Setenv("SMOLMAILER_DKIM_SIGNER_ED25519_PRIVATEKEY_PATH", "/foo/ed25519")

	ConfigDefaults()
	cfg := &Config{}
	err := viper.UnmarshalExact(cfg)
	require.NoError(t, err)

	//allKeys := viper.AllKeys()
	//fmt.Printf("%s", allKeys[0])

	assert.Equal(t, "rsa-selector", viper.Get("dkim.signer.rsa.selector"))
	assert.Equal(t, "mail.example.com", cfg.MailDomain)
	assert.Equal(t, "acme@example.com", cfg.Acme.Email)
	assert.Len(t, cfg.Dkim.Signer, 2)
	assert.NotEmpty(t, cfg.Dkim.Signer["rsa"])
	assert.Equal(t, "rsa-selector", cfg.Dkim.Signer["rsa"].Selector)
	assert.NotEmpty(t, cfg.Dkim.Signer["ed25519"])
	assert.Equal(t, "ed25519-selector", cfg.Dkim.Signer["ed25519"].Selector)
}
