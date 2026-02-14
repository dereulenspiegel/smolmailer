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

func TestProperRSAKeyRepresentation(t *testing.T) {
	expectedPubKeyForm := `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr86o/XwR3StiqM8NMwkA2iZTx7ch6GCDCZO4qxWTSAa73RJKYVQTqQLwp3f4qPX+RfM/JhAH8sgd0qPWWI+kbpp4NxC8fMkQO8QKXDlo0dGsMvjL+OaerAi307nxmGiEAw+uk9jnGNyStaLy6Npy3rx9SJFyvMhUkFqDqZdP9SXEz1mqs5f+WVFun9/SLyTNpqrM6i59iK9nJw48Rg+obtY+P1acX0kxUKYI1pYFfdilN6nScnXufJUSo1u+zcqrQQemrbpjyZlyomzgms12ZIAYmy1R6j88QMlFzIL8QabtUF9r4GJTKYvPLYts0M7h/g0juDOMNKIher+zblqpTwIDAQAB`
	privateKeyPEM := `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvzqj9fBHdK2Ko
zw0zCQDaJlPHtyHoYIMJk7irFZNIBrvdEkphVBOpAvCnd/io9f5F8z8mEAfyyB3S
o9ZYj6Rumng3ELx8yRA7xApcOWjR0awy+Mv45p6sCLfTufGYaIQDD66T2OcY3JK1
ovLo2nLevH1IkXK8yFSQWoOpl0/1JcTPWaqzl/5ZUW6f39IvJM2mqszqLn2Ir2cn
DjxGD6hu1j4/VpxfSTFQpgjWlgV92KU3qdJyde58lRKjW77NyqtBB6atumPJmXKi
bOCazXZkgBibLVHqPzxAyUXMgvxBpu1QX2vgYlMpi88ti2zQzuH+DSO4M4w0oiF6
v7NuWqlPAgMBAAECggEAD8Y9jXkAv//bkK/7TDVQ7pdPycoEcILwXv9H1jn6XBUW
mCXC/MFRfkcK7CEsnjnBlenXJFrTNmp+7955e2VwEz3S7ttBPk/AICIH7UciwOjM
8vSLQLWt+QZTOtvNR1KMExuTcM/zybGeNvlRov5Zc44lY58r/1pY6Ww7B2V8ls9Q
IK17RgbbfmeWAQw9n3qmB6ea96TSMgyL7QGmQIkfIo2FWJJFHu2BRWgExqIn2HF9
MFGw/PbsCFhXa3auwlWTfDDjzomoRUrLXnPtElZstAbKO0Bslc+SzAlqxM6l+8xH
2LFfU0ZyAsJrCwp27YVM+FtX3D7/KzN/18B9sBAhWQKBgQDrm3oZNpKXtcI6yxlV
btvhMlzyIspBQLp4r6pxXKhSpK1f+xMv4z8omOfEX4btBb4TjXz6N9NoYezEjAN2
q0Vu/ZJjAyetl4+EnfZFIWYSb8xvJY+Nm5uDN8unuDUXrNtQyBT03L9Y+aMXDfUr
AAYuZZzPQqBOEYnHCFQUPdpu4wKBgQC/BiZM2uuXUGd3Xqs7+AMk3MZcfNcD3Y3X
g433e8Qx6qMeZ3TR/9msLkpxKV3YDg13a+kxReKi7VmtOTmfnD58BfhrsyiGF2+k
Y5p1EJ9nVPrJbUIPcDK1aN/VY1EJWUz0aoSZB8SWnSJTFnsFJJubY/N2VTS11cbp
ejLY/ofbpQKBgQCZzIN2w/4LlLW2pW/jKhvUtIih833t/K/9Kkbr+11RnXgjyIUs
5H4NJUteEDHGtdHvd5QWzqxtXkctwmxcYc9QdazCf4O+OMqR+n+RfwzfiiV8hJti
CCsLDDggQwo9azQ7VnD/qr4p+cOxwAXDzR872E71qPt2GtLCnzgrgnj9mwKBgQCV
AUYE80uMN5LNwVHOsHI7Yd91K4hJIpxO/PZTkv6CdWWSBN9SI8H2lhFJXhwuuR92
BP3ciofz0TL/dUDmqOjws3OJBzJYDpXuZCeKo1HEN7x8PLan9jwH1+uptxPyN+9Y
RHJ0MGP/nEi3CTUi2OBsgLXbmzFHmZ7UZpadP0ZYZQKBgGtkeRJWXme6PpJL+oHo
MI3smPMuerqUPf5zRLrmuywGzWLQcP9/4fzELSezFFSL2LBuMgrq036lit151IGS
Bm9vlUfybWzDHag+i3Hnf9v/JwkJNyVvECa3mpaHXncvHm6lm0EIhRNJuXVm7nn4
kMnPN0l9ZTtovHHRPVwErZ1f
-----END PRIVATE KEY-----
	`

	privKey, err := ParseDkimKey(privateKeyPEM)
	require.NoError(t, err)
	pubKey, err := pubKey(privKey)
	require.NoError(t, err)
	dkimKey, keyType, err := dnsDkimKey(pubKey)
	require.NoError(t, err)

	assert.Equal(t, "rsa", keyType)
	assert.Equal(t, expectedPubKeyForm, dkimKey)

}
