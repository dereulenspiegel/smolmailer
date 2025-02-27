package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
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
	domainPrivateKey, testCert, err := generateTestCertificate()
	require.NoError(t, err)

	c := NewInMemoryCache()
	err = c.AddCertificate(testCert, domainPrivateKey)
	require.NoError(t, err)

	certMain, err := c.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotNil(t, certMain)
	assert.NotNil(t, certMain.PrivateKey)
	parsedCert, err := x509.ParseCertificate(certMain.Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, parsedCert.DNSNames, "example.com")
}

func TestCleanExpiredCertificates(t *testing.T) {
	domainPrivateKey, testCert, err := generateTestCertificate(func(cert *x509.Certificate) {
		cert.NotAfter = time.Now().Add(time.Minute * -1)
	})
	require.NoError(t, err)
	c := NewInMemoryCache()
	err = c.AddCertificate(testCert, domainPrivateKey)
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

func TestRetrieveExpiringDomain(t *testing.T) {
	domainPrivateKey, testCert, err := generateTestCertificate(func(cert *x509.Certificate) {
		cert.NotAfter = time.Now().Add(time.Hour * (29 * 24))
	})
	require.NoError(t, err)
	c := NewInMemoryCache()
	err = c.AddCertificate(testCert, domainPrivateKey)
	require.NoError(t, err)

	expiringDomains, err := c.ExpiringDomains(time.Hour * 24 * 30)
	require.NoError(t, err)
	assert.Len(t, expiringDomains, 1)
	assert.Contains(t, expiringDomains[0], "example.com")
	assert.Contains(t, expiringDomains[0], "sub.example.com")
}

func generateTestCertificate(fTemplate ...func(*x509.Certificate)) (crypto.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
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
	publicKey := privateKey.Public()
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	buf := &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, nil, err
	}
	return privateKey, buf.Bytes(), nil
}

func TestFilebackedCache(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "caches.json")
	fc, err := NewFileBackedCache(cacheFile)
	require.NoError(t, err)

	cert, err := fc.GetCertForDomain("example.com")
	require.Error(t, err)
	require.Empty(t, cert)

	key, testCert, err := generateTestCertificate()
	require.NoError(t, err)
	err = fc.AddCertificate(testCert, key)
	require.NoError(t, err)

	cert, err = fc.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, cert)

	fc2, err := NewFileBackedCache(cacheFile)
	require.NoError(t, err)

	cert, err = fc2.GetCertForDomain("example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, cert)
}
