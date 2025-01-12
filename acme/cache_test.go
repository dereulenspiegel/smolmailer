package acme

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryGetCertificateForDomain(t *testing.T) {
	c := NewInMemoryCache()
	c.certs.Store("sub.example.com", &tls.Certificate{
		Certificate: [][]byte{[]byte("sub.example.com")},
	})
	c.certs.Store("*.example.com", &tls.Certificate{
		Certificate: [][]byte{[]byte("*.example.com")},
	})

	cert, err := c.GetCertForDomain("sub.example.com")
	require.NoError(t, err)
	assert.Equal(t, []byte("sub.example.com"), cert.Certificate[0])

	cert, err = c.GetCertForDomain("another.example.com")
	require.NoError(t, err)
	assert.Equal(t, []byte("*.example.com"), cert.Certificate[0])

	cert, err = c.GetCertForDomain("google.com")
	require.Nil(t, cert)
	assert.Error(t, err)
}

func TestAddCertificate(t *testing.T) {
	testCert, err := generateTestCertificate()
	require.NoError(t, err)

	c := NewInMemoryCache()
	err = c.AddCertificate(testCert)
	require.NoError(t, err)

	certMain, err := c.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotNil(t, certMain)
	parsedCert, err := x509.ParseCertificate(certMain.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, parsedCert.DNSNames, "example.com")
}

func TestCleanExpiredCertificates(t *testing.T) {
	testCert, err := generateTestCertificate(func(cert *x509.Certificate) {
		cert.NotAfter = time.Now().Add(time.Minute * -1)
	})
	require.NoError(t, err)
	c := NewInMemoryCache()
	err = c.AddCertificate(testCert)
	require.NoError(t, err)

	retrievedCert, err := c.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotNil(t, retrievedCert)

	err = c.CleanupExpired()
	require.NoError(t, err)

	retrievedCert, err = c.GetCertForDomain("example.com")
	assert.Nil(t, retrievedCert)
	assert.Error(t, err)
}

func generateTestCertificate(fTemplate ...func(*x509.Certificate)) ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "sub.example.com"},
	}
	for _, f := range fTemplate {
		f(&template)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	certDER, err := x509.CreateCertificate(nil, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
