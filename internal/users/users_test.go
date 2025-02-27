package users

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateUser(t *testing.T) {
	passwdDecoder, err := argon2Decoder()
	require.NoError(t, err)
	us := &UserService{
		logger:        slog.Default(),
		passwdDecoder: passwdDecoder,
	}
	userYaml := []byte(`
- username: authelia
  password: $argon2id$v=19$m=2097152,t=2,p=4$SdrcJ6rSDvgFp3LIbDDZYw$O/iJ19X9KA3OZlsxx7UNy/Rr4rbubKz6sp3G6s4D3AA
  from: auhelia@example.com
`)
	err = us.unmarshalConfig(userYaml)
	require.NoError(t, err)

	err = us.Authenticate("authelia", "foobar")
	assert.NoError(t, err)
}

func TestIsValidSender(t *testing.T) {
	passwdDecoder, err := argon2Decoder()
	require.NoError(t, err)
	us := &UserService{
		logger:        slog.Default(),
		passwdDecoder: passwdDecoder,
	}
	userYaml := []byte(`
- username: authelia
  password: $argon2id$v=19$m=2097152,t=2,p=4$SdrcJ6rSDvgFp3LIbDDZYw$O/iJ19X9KA3OZlsxx7UNy/Rr4rbubKz6sp3G6s4D3AA
  from: authelia@example.com
`)
	err = us.unmarshalConfig(userYaml)
	require.NoError(t, err)

	valid := us.IsValidSender("authelia", "authelia@example.com")
	assert.True(t, valid)
}
