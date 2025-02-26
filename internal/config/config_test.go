package config

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsingEnvVars(t *testing.T) {
	t.Setenv("SMOLMAILER_ACME_EMAIL", "acme@example.com")
	t.Setenv("SMOLMAILER_MAILDOMAIN", "mail.example.com")

	ConfigDefaults()
	cfg := &Config{}
	err := viper.UnmarshalExact(cfg)
	require.NoError(t, err)

	allKeys := viper.AllKeys()
	fmt.Printf("%s", allKeys[0])

	assert.Equal(t, "mail.example.com", cfg.MailDomain)
	assert.Equal(t, "acme@example.com", cfg.Acme.Email)
}
