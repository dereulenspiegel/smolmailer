package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

type DNS01Config struct {
	DontWaitForPropagation bool          `mapstructure:"dontWaitForPropagation"`
	PropagationTimeout     time.Duration `mapstructure:"propagationTimeout"`
	ProviderName           string        `mapstructure:"providerName"`
}

type Config struct {
	Dir             string        `mapstructure:"dir"`
	Email           string        `mapstructure:"email"`
	CAUrl           string        `mapstructure:"caUrl"`
	RenewalInterval time.Duration `mapstructure:"renewalInterval"`
	AutomaticRenew  bool          `mapstructure:"automaticRenew"`
	DNS01           *DNS01Config  `mapstructure:"dns01"`

	dns01Provider challenge.Provider
	httpClient    *http.Client // Set custom http client for testing
}

func (c *Config) IsValid() error {
	if c == nil {
		return fmt.Errorf("ACME config is nil")
	}
	if c.Email == "" {
		return fmt.Errorf("you need to specify an acme account email address")
	}
	if c.DNS01.ProviderName == "" {
		return fmt.Errorf("you need to specify a DNS-01 provider name, see https://go-acme.github.io/lego/dns/index.html")
	}
	return nil
}

type AcmeTls struct {
	ModifiableCertCache

	cfg              *Config
	acmeClient       *lego.Client
	domainPrivateKey *ecdsa.PrivateKey

	logger *slog.Logger
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

// NewAcme returns a new AcmeTls manager
func NewAcme(ctx context.Context, logger *slog.Logger, cfg *Config) (*AcmeTls, error) {
	if cfg.CAUrl == "" {
		cfg.CAUrl = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if err := os.MkdirAll(cfg.Dir, 0770); err != nil {
		return nil, fmt.Errorf("failed to ensure acme directory %s exists: %w", cfg.Dir, err)
	}

	a := &AcmeTls{
		cfg:    cfg,
		logger: logger,
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
	if acmeCfg.HTTPClient == nil {
		acmeCfg.HTTPClient = http.DefaultClient
	}

	client, err := lego.NewClient(acmeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create acme client: %w", err)
	}
	a.acmeClient = client

	chlgOpts := []dns01.ChallengeOption{}
	if cfg.DNS01.DontWaitForPropagation {
		chlgOpts = append(chlgOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	chlgOpts = append(chlgOpts, dns01.AddDNSTimeout(cfg.DNS01.PropagationTimeout))

	dns01Provider := cfg.dns01Provider
	if dns01Provider == nil {
		dns01Provider, err = dns.NewDNSChallengeProviderByName(cfg.DNS01.ProviderName)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS-01 challenge provider %s: %w", cfg.dns01Provider, err)
		}
	}
	if err := client.Challenge.SetDNS01Provider(dns01Provider, chlgOpts...); err != nil {
		return nil, fmt.Errorf("failed to set %s as DNS-01 challenge provider: %w", cfg.dns01Provider, err)
	}
	if err := a.ensureRegistration(user); err != nil {
		return nil, err
	}
	if cfg.AutomaticRenew {
		go a.goCheckRenew(ctx)
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

// CheckRenew checks every certificate if it needs renewal based on Config.RenewalInterval and renews every certificate which needs renewal
func (a *AcmeTls) CheckRenew() (err error) {
	renewDomains, err := a.ExpiringDomains(a.cfg.RenewalInterval)
	if err != nil {
		return fmt.Errorf("failed to query expiring domains: %w", err)
	}
	for _, domains := range renewDomains {
		if err := a.ObtainCertificate(domains...); err != nil {
			return fmt.Errorf("failed to renew domains [%s]: %w", strings.Join(domains, ","), err)
		}
	}
	return nil
}

func (a *AcmeTls) goCheckRenew(ctx context.Context) {
	logger := a.logger.With("component", "acme.goCheckRenew")
	cctx, cancel := context.WithCancel(ctx)
	tick := time.NewTicker(time.Hour * 12)
	defer cancel()
	if err := a.CheckRenew(); err != nil {
		logger.Error("failed to automatically renew certificates", "err", err)
	}
	for {
		select {
		case <-cctx.Done():
			tick.Stop()
			return
		case <-tick.C:
			if err := a.CheckRenew(); err != nil {
				logger.Error("failed to automatically renew certificates", "err", err)
			}
		default:
			// Sleep a bit to yield the goroutine
			time.Sleep(time.Second * 10)
		}
	}
}

// ObtainCertificate obtains a certificate for every specified domain and puts it into the CertCache
func (a *AcmeTls) ObtainCertificate(domains ...string) error {
	domainsToObtain := []string{}
	logger := a.logger.With("domains", strings.Join(domains, ","))

	// Do not try to obtain certificates for domains we already have valid certs for
	for _, domain := range domains {
		cert, err := a.GetCertForDomain(domain)
		if err != nil || !a.isCertNotExpired(cert) {
			logger.With("err", err, "domain", domain).Info("certificate for domain not in cache or expired")
			domainsToObtain = append(domainsToObtain, domain)
		}
	}

	if len(domainsToObtain) == 0 {
		logger.Info("certificates for all domains are cached and do not need to be requested")
		// Nothing to do we have all the domains already
		return nil
	}

	logger = logger.With("requestingDomains", strings.Join(domainsToObtain, ","))
	logger.Info("requesting certificate for domains")
	request := certificate.ObtainRequest{
		PrivateKey: a.domainPrivateKey,
		Bundle:     true,
		Domains:    domainsToObtain,
	}
	certResource, err := a.acmeClient.Certificate.Obtain(request)
	if err != nil {
		logger.With("err", err).Error("failed to request certificates for domains")
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}
	return a.AddCertificate(certResource.Certificate, a.domainPrivateKey)
}

func (a *AcmeTls) isCertNotExpired(tlsCert *tls.Certificate) bool {
	logger := a.logger
	// Check if any cert in the chain is expired
	for _, derBytes := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			logger.With("err", err).Error("failed to parse certificate from cache during expiration check")
			// Unparseable certificates should be renewed and therefore count as expired
			return false
		}
		if time.Now().After(cert.NotAfter) {
			return true
		}
	}
	return false
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
	err = os.WriteFile(userFile, userData, 0600)
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

// CertCache is a cache for certificates to be used in a *tls.Config
type CertCache interface {
	GetCertForDomain(domain string) (*tls.Certificate, error)
	ExpiringDomains(interval time.Duration) ([][]string, error)
}

// ModifiableCertCache is a CertCache which can be modified by adding certificates. Certificate deletion is currently not in scope of this interface
type ModifiableCertCache interface {
	CertCache
	AddCertificate(pemData []byte, privateKey crypto.PrivateKey) error
}

// NewTlsConfig returns a *tls.Config which serves certificates from the specified CertCache
func NewTlsConfig(cache CertCache) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cache.GetCertForDomain(hello.ServerName)
		},
		MinVersion: tls.VersionTLS12,
	}
}
