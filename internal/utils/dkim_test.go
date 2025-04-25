package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeDkimPrivateKey(t *testing.T) {
	privKeyStr := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICBZH0aA1bNViXPHA0xIzGWHX4LiiBs72/K1o6iTWM0X
-----END PRIVATE KEY-----`

	privKey, err := ParseDkimKey(privKeyStr)
	require.NoError(t, err)
	assert.NotNil(t, privKey)
}

func TestCreateDnsRecords(t *testing.T) {
	dkimKeyPem := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJhGWXSKnABUEcPSYV00xfxhR6sf/3iEsJfrOxE3H/3r
-----END PRIVATE KEY-----
			`

	privateKey, err := ParseDkimKey(dkimKeyPem)
	require.NoError(t, err)

	txtVal, err := DkimTxtRecordContent(privateKey)
	require.NoError(t, err)
	assert.Equal(t, "v=DKIM1;k=ed25519;h=sha256;p=cg0U0fEFhhfu5KyEzQdS5WlErbZnF2YvUZIKnVSmxKg=", txtVal)
}
