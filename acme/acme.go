package acme

import (
	"crypto/tls"
)

type CertCache interface {
	GetCertForDomain(domain string) (*tls.Certificate, error)
}

type ModifiableCertCache interface {
	CertCache
	AddCertificate(domain string, pemData []byte) error
}

func NewTlsConfig(cache CertCache) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cache.GetCertForDomain(hello.ServerName)
		},
		MinVersion: tls.VersionTLS12,
	}
}
