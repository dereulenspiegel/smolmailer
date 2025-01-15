package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PebbleContainer struct {
	testcontainers.Container
}

func SetupPebble(ctx context.Context, dnsServer string) (*PebbleContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/letsencrypt/pebble:latest",
		ExposedPorts: []string{"14000/tcp", "15000/tcp"},
		WaitingFor:   wait.ForLog("ACME directory available at: .*").AsRegexp(),
		Cmd:          []string{"-dnsserver", dnsServer},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}
	return &PebbleContainer{container}, nil
}

func (p *PebbleContainer) AcmeUrl(ctx context.Context) (string, error) {
	ip, err := p.Host(ctx)
	if err != nil {
		return "", err
	}
	mappedPort, err := p.MappedPort(ctx, "14000")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s:%d/dir", ip, mappedPort.Int()), nil
}

func (p *PebbleContainer) GetRootCerts(ctx context.Context) (rootCerts []*x509.Certificate, err error) {
	ip, err := p.Host(ctx)
	if err != nil {
		return nil, err
	}
	mappedPort, err := p.MappedPort(ctx, "15000")
	if err != nil {
		return nil, err
	}

	rootCertUrl := fmt.Sprintf("https://%s:%d/roots/0", ip, mappedPort.Int())
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := httpClient.Get(rootCertUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve root cert from pebble: %w", err)
	}
	defer resp.Body.Close()
	rootCerts = append(rootCerts, resp.TLS.PeerCertificates...) // the Directory and management API are not signed by the root CA managed by Pebble
	pemData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download root cert from pebble: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid pem data for root cert from pebble")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root cert from pem: %w", err)
	}
	rootCerts = append(rootCerts, rootCert)
	return
}

func (p *PebbleContainer) HttpClient(ctx context.Context) (*http.Client, error) {
	rootCerts, err := p.GetRootCerts(ctx)
	if err != nil {
		return nil, err
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}
	for _, rootCert := range rootCerts {
		certPool.AddCert(rootCert)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	return httpClient, nil
}

type PebbleChallengeServer struct {
	testcontainers.Container
}

func SetupPebbleChallengeServer(ctx context.Context) (*PebbleChallengeServer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/letsencrypt/pebble-challtestsrv:latest",
		ExposedPorts: []string{"8055/tcp", "8053/udp"},
		WaitingFor:   wait.ForLog("Starting challenge servers"),
		Cmd:          []string{"-defaultIPv4", "127.0.0.1", "-defaultIPv6", "::1", "-dns01", "[::]:8053,:8053", "-http01", "", "-tlsalpn01", ""},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}
	return &PebbleChallengeServer{container}, nil
}

func (p *PebbleChallengeServer) DnsServerAddresses(ctx context.Context) (containerAddr string, localAddr string, err error) {
	ip, err := p.ContainerIP(ctx)
	if err != nil {
		return "", "", err
	}
	mappedPort, err := p.MappedPort(ctx, "8053/udp")
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%s:%d", ip, 8053), fmt.Sprintf("127.0.0.1:%d", mappedPort.Int()), nil
}

func (p *PebbleChallengeServer) ManagementUrl(ctx context.Context) (string, error) {
	ip, err := p.Host(ctx)
	if err != nil {
		return "", err
	}
	mappedPort, err := p.MappedPort(ctx, "8055")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s:%d", ip, mappedPort.Int()), nil
}

func (p *PebbleChallengeServer) DNS01ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	managementUrl, err := p.ManagementUrl(ctx)
	if err != nil {
		return nil, err
	}
	return &pebbleDNS01ChallengeProvider{
		pebbleUrl:  managementUrl,
		httpClient: &http.Client{},
	}, nil
}

type pebbleDNS01ChallengeProvider struct {
	pebbleUrl  string
	httpClient *http.Client
}

type pebbleChallengeRequest struct {
	Host  string `json:"host"`
	Value string `json:"value,omitempty"`
}

func (p *pebbleDNS01ChallengeProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	req := pebbleChallengeRequest{
		Host:  info.EffectiveFQDN,
		Value: info.Value,
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	resp, err := p.httpClient.Post(fmt.Sprintf("%s/set-txt", p.pebbleUrl), "application/json", buf)
	if err != nil {
		return fmt.Errorf("failed to send request to pebble challenge server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		errorBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read error body for status %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("failed request with status %d: %s", resp.StatusCode, string(errorBody))
	}
	return nil
}

func (p *pebbleDNS01ChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	req := pebbleChallengeRequest{Host: info.EffectiveFQDN}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	resp, err := p.httpClient.Post(fmt.Sprintf("%s/clear-txt", p.pebbleUrl), "application/json", buf)
	if err != nil {
		return fmt.Errorf("failed to send request to pebble challenge server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		errorBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read error body for status %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("failed request with status %d: %s", resp.StatusCode, string(errorBody))
	}
	return nil
}
