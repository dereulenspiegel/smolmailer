package utils

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, "v=DKIM1;k=ed25519;h=sha256;p=MCowBQYDK2VwAyEAcg0U0fEFhhfu5KyEzQdS5WlErbZnF2YvUZIKnVSmxKg", txtVal)
}
