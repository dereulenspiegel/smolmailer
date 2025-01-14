package acme

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type inMemoryCertCache struct {
	certs *sync.Map
	lock  *sync.Mutex
}

func NewInMemoryCache() *inMemoryCertCache {
	return &inMemoryCertCache{
		certs: &sync.Map{},
		lock:  &sync.Mutex{},
	}
}

func (i *inMemoryCertCache) GetCertForDomain(domain string) (*tls.Certificate, error) {
	if cert, exists := i.certs.Load(domain); exists {
		return cert.(*tls.Certificate), nil
	}

	wildcard := "*." + strings.Join(strings.Split(domain, ".")[1:], ".")
	if cert, exists := i.certs.Load(wildcard); exists {
		return cert.(*tls.Certificate), nil
	}
	return nil, errors.New("no matching cert found")
}

func (i *inMemoryCertCache) AddCertificate(pemData []byte) error {
	i.lock.Lock()
	defer i.lock.Unlock()
	certs := []*x509.Certificate{}
	for block, rest := pem.Decode(pemData); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)

		default:
			return fmt.Errorf("invalid PEM block of type %s", block.Type)
		}
	}

	dnsNames := []string{}
	tlsCert := &tls.Certificate{}
	for _, cert := range certs {
		dnsNames = append(dnsNames, cert.DNSNames...)
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}

	for _, dnsName := range dnsNames {
		i.certs.Store(dnsName, tlsCert)
	}
	return nil
}

func (i *inMemoryCertCache) CleanupExpired() error {
	i.certs.Range(func(key any, val any) bool {
		tlsCert := val.(*tls.Certificate)
		isExpired := false
		for _, derBytes := range tlsCert.Certificate {
			cert, err := x509.ParseCertificate(derBytes)
			if err != nil {
				// Certificate seems invalid, remove from store
				i.certs.Delete(key)
				break
			} else {
				if time.Now().After(cert.NotAfter) {
					isExpired = true
					break
				}
			}
		}
		if isExpired {
			// If any certificate in the chain is expired, remove it
			i.certs.Delete(key)
		}

		return true
	})
	return nil
}

type fileBackedCache struct {
	inMemoryCertCache

	fileLock *sync.Mutex
	filePath string
}

func NewFileBackedCache(filePath string) (*fileBackedCache, error) {
	return &fileBackedCache{
		fileLock:          &sync.Mutex{},
		filePath:          filePath,
		inMemoryCertCache: *NewInMemoryCache(),
	}, nil
}

type fileData struct {
	Certificates map[string]string
}

func (f *fileBackedCache) GetCertForDomain(domain string) (*tls.Certificate, error) {
	return f.inMemoryCertCache.GetCertForDomain(domain)
}

func (f *fileBackedCache) AddCertificate(pemData []byte) error {
	err := f.inMemoryCertCache.AddCertificate(pemData)
	if err != nil {
		return err
	}
	return f.store()
}

func (f *fileBackedCache) store() error {
	f.fileLock.Lock()
	defer f.fileLock.Unlock()
	fData := &fileData{
		Certificates: make(map[string]string),
	}

	f.inMemoryCertCache.certs.Range(func(key any, value any) bool {
		tlsCert := value.(*tls.Certificate)
		buf := bytes.NewBuffer([]byte{})
		for _, certBytes := range tlsCert.Certificate {
			pem.Encode(buf, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certBytes,
			})
		}
		domain := key.(string)
		pemData := base64.RawStdEncoding.EncodeToString(buf.Bytes())
		fData.Certificates[domain] = pemData
		return true
	})

	fDataBytes, err := json.Marshal(fData)
	if err != nil {
		return err
	}
	return os.WriteFile(f.filePath, fDataBytes, 0600)
}

func (f *fileBackedCache) Load() error {
	f.fileLock.Lock()
	defer f.fileLock.Unlock()

	jsonBytes, err := os.ReadFile(f.filePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate data from %s: %w", f.filePath, err)
	}
	fData := &fileData{}
	err = json.Unmarshal(jsonBytes, fData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal certificate data from %s: %w", f.filePath, err)
	}

	for domain, pemDataString := range fData.Certificates {
		pemBytes, err := base64.RawStdEncoding.DecodeString(pemDataString)
		if err != nil {
			return fmt.Errorf("failed to decode PEM bytes for domain %s from %s: %w", domain, f.filePath, err)
		}
		if err := f.inMemoryCertCache.AddCertificate(pemBytes); err != nil {
			return fmt.Errorf("failed to add certificate for domain %s: %w", f.filePath, err)
		}
	}
	return nil
}
