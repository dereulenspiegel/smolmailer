package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

const (
	userFile             = "user.json"
	domainPrivateKeyFile = "private.key.pem"
	certCacheFile        = "certs.json"
	pemTypeEcPrivateKey  = "EC PRIVATE KEY"
)

type Config struct {
	Dir               string
	Email             string
	CAUrl             string
	DNS01ProviderName string
	DNS01Provider     challenge.Provider

	dns01DontWaitForPropagation bool         //Disable looking up the autorative DNS in testing
	httpClient                  *http.Client // Set custom http client for testing
}

type AcmeTls struct {
	ModifiableCertCache

	cfg              *Config
	acmeClient       *lego.Client
	domainPrivateKey *ecdsa.PrivateKey
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   string

	key *ecdsa.PrivateKey
}

func (a *acmeUser) GetEmail() string {
	return a.Email
}

func (a *acmeUser) GetRegistration() *registration.Resource {
	return a.Registration
}

func (a *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

func NewAcme(cfg *Config) (*AcmeTls, error) {
	if cfg.CAUrl == "" {
		cfg.CAUrl = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if err := os.MkdirAll(cfg.Dir, 0770); err != nil {
		return nil, fmt.Errorf("failed to ensure acme directory %s exists: %w", cfg.Dir, err)
	}

	a := &AcmeTls{
		cfg: cfg,
	}
	domainPrivateKey, err := a.loadDomainPrivateKey()
	if err != nil {
		return nil, err
	}
	a.domainPrivateKey = domainPrivateKey

	a.ModifiableCertCache, err = NewFileBackedCache(filepath.Join(a.cfg.Dir, certCacheFile))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}

	user, err := a.getUser()
	if err != nil {
		return nil, err
	}
	acmeCfg := lego.NewConfig(user)
	acmeCfg.Certificate.KeyType = certcrypto.EC256
	acmeCfg.CADirURL = cfg.CAUrl
	acmeCfg.HTTPClient = cfg.httpClient

	client, err := lego.NewClient(acmeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create acme client: %w", err)
	}
	a.acmeClient = client

	chlgOpts := []dns01.ChallengeOption{}
	if cfg.dns01DontWaitForPropagation {
		chlgOpts = append(chlgOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}

	dns01Provider := cfg.DNS01Provider
	if dns01Provider == nil {
		dns01Provider, err = dns.NewDNSChallengeProviderByName(cfg.DNS01ProviderName)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS-01 challenge provider %s: %s", cfg.DNS01Provider, err)
		}
	}
	if err := client.Challenge.SetDNS01Provider(dns01Provider, chlgOpts...); err != nil {
		return nil, fmt.Errorf("failed to set %s as DNS-01 challenge provider: %w", cfg.DNS01Provider, err)
	}
	if err := a.ensureRegistration(user); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AcmeTls) ensureRegistration(user *acmeUser) error {
	if user.Registration == nil {
		// Register new user
		reg, err := a.acmeClient.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register acme user %s: %w", a.cfg.Email, err)
		}
		user.Registration = reg
		if err := a.writeUser(user); err != nil {
			return fmt.Errorf("failed to persist user data and registration: %w", err)
		}
	}
	return nil
}

func (a *AcmeTls) ObtainCertificate(domains ...string) error {
	request := certificate.ObtainRequest{
		PrivateKey: a.domainPrivateKey,
		Bundle:     true,
		Domains:    domains,
	}
	certResource, err := a.acmeClient.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}
	return a.AddCertificate(certResource.Certificate, a.domainPrivateKey)
}

func (a *AcmeTls) loadDomainPrivateKey() (key *ecdsa.PrivateKey, err error) {
	privKeyPath := filepath.Join(a.cfg.Dir, domainPrivateKeyFile)
	pemData, err := os.ReadFile(privKeyPath)
	if err != nil && os.IsExist(err) {
		return nil, fmt.Errorf("failed to read domain private key from %s: %w", privKeyPath, err)
	} else if err != nil && os.IsNotExist(err) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate domain private key: %w", err)
		}
		derBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal domain private key: %w", err)
		}
		pemBlock := &pem.Block{
			Type:  pemTypeEcPrivateKey,
			Bytes: derBytes,
		}
		privKeyFile, err := os.OpenFile(privKeyPath, os.O_CREATE|os.O_WRONLY, 0660)
		if err != nil {
			return nil, fmt.Errorf("failed to open private key file %s: %w", privKeyPath, err)
		}
		defer privKeyFile.Close()
		err = pem.Encode(privKeyFile, pemBlock)
		if err != nil {
			return nil, fmt.Errorf("failed to write private key to file %s: %w", privKeyPath, err)
		}
		return key, err
	}
	block, _ := pem.Decode(pemData)
	if block.Type != pemTypeEcPrivateKey {
		return nil, fmt.Errorf("invalid pem block type %s", block.Type)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func (a *AcmeTls) writeUser(user *acmeUser) error {
	userFile := filepath.Join(a.cfg.Dir, userFile)
	derKey, err := x509.MarshalECPrivateKey(user.key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyBlock := &pem.Block{
		Type:  pemTypeEcPrivateKey,
		Bytes: derKey,
	}
	pemString := string(pem.EncodeToMemory(keyBlock))
	user.PrivateKey = pemString
	userData, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal userdata: %w", err)
	}
	err = os.WriteFile(userFile, userData, 0660)
	if err != nil {
		return fmt.Errorf("failed to write user data to %s: %w", userFile, err)
	}
	return nil
}

func (a *AcmeTls) getUser() (user *acmeUser, err error) {
	userFile := filepath.Join(a.cfg.Dir, userFile)
	userData, err := os.ReadFile(userFile)
	if err != nil && os.IsExist(err) {
		return nil, fmt.Errorf("failed to read user data from %s: %w", userFile, err)
	} else if err != nil && os.IsNotExist(err) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key for user %s: %w", a.cfg.Email, err)
		}
		user = &acmeUser{
			Email: a.cfg.Email,
			key:   privateKey,
		}
		err = a.writeUser(user)
		if err != nil {
			return nil, err
		}
	} else {
		user = &acmeUser{}
		err = json.Unmarshal(userData, user)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal user data from %s:%w", userFile, err)
		}
		block, _ := pem.Decode([]byte(user.PrivateKey))
		if block == nil {
			return nil, fmt.Errorf("invalid pem block for users private key: %w", err)
		}
		if block.Type != pemTypeEcPrivateKey {
			return nil, fmt.Errorf("invalid pem block type for user private key: %s", block.Type)
		}
		privKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key for user: %w", err)
		}
		user.key = privKey
	}
	return user, nil
}

type CertCache interface {
	GetCertForDomain(domain string) (*tls.Certificate, error)
}

type ModifiableCertCache interface {
	CertCache
	AddCertificate(pemData []byte, privateKey crypto.PrivateKey) error
}

func NewTlsConfig(cache CertCache) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cache.GetCertForDomain(hello.ServerName)
		},
		MinVersion: tls.VersionTLS12,
	}
}
