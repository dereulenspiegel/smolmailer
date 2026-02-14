package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/dereulenspiegel/smolmailer/internal/utils"
	"github.com/spf13/viper"
)

type PrivateKey struct {
	Value  string `mapstructure:"key"`
	Path   string `mapstructure:"path"`
	keyVal string
}

func (p *PrivateKey) IsValid() error {

	if p == nil || (p.Value == "" && p.Path == "") {
		return errors.New("either key or path must be set for private key")
	}
	return nil
}

func (p *PrivateKey) GetKey() (string, error) {
	if p == nil {
		return "", errors.New("private key not set")
	}
	if p.Value != "" {
		return p.Value, nil
	}
	pemBytes, err := os.ReadFile(p.Path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file from %s: %w", p.Path, err)
	}
	return string(pemBytes), nil
}

type DkimPrivateKeys struct {
	Ed25519 *PrivateKey `mapstructure:"ed25519"`
	RSA     *PrivateKey `mapstructure:"rsa"`
}

func (d *DkimPrivateKeys) IsValid() error {
	if d == nil {
		return errors.New("DKIM private keys must be configured")
	}
	edErr := d.Ed25519.IsValid()
	rsaErr := d.RSA.IsValid()
	if edErr != nil && rsaErr != nil {
		return errors.Join(edErr, rsaErr)
	}
	return nil
}

type DkimOpts struct {
	Signer map[string]*DkimSigner `mapstructure:"signer"`
}

type DkimSigner struct {
	Selector   string      `mapstructure:"selector"`
	PrivateKey *PrivateKey `mapstructure:"privateKey"`
}

func (d *DkimOpts) IsValid() error {
	if d == nil {
		return errors.New("dkim options are not set")
	}
	if len(d.Signer) == 0 {
		return errors.New("no DKIM signer configured")
	}
	for _, signer := range d.Signer {
		if signer.PrivateKey == nil {
			return errors.New("DKIM private key must be set")
		}
		if err := signer.PrivateKey.IsValid(); err != nil {
			return err
		}
		if len(signer.Selector) == 0 {
			return errors.New("DKIM selector must be set")
		}
	}
	return nil
}

type TestingOpts struct {
	MxPorts  []int
	MxResolv func(string) ([]*net.MX, error)
}

type Config struct {
	MailDomain      string       `mapstructure:"mailDomain"`
	TlsDomain       string       `mapstructure:"tlsDomain"`
	ListenAddr      string       `mapstructure:"listenAddr"`
	ListenTls       bool         `mapstructure:"listenTls"`
	LogLevel        string       `mapstructure:"logLevel"`
	SendAddr        string       `mapstructure:"sendAddr"`
	QueuePath       string       `mapstructure:"queuePath"`
	UserFile        string       `mapstucture:"userFile"`
	AllowedIPRanges []string     `mapstructure:"allowedIPRanges"`
	Acme            *acme.Config `mapstructure:"acme"`
	Dkim            *DkimOpts    `mapstructure:"dkim"`

	TestingOpts *TestingOpts `mapstructure:",omitempty"`
}

func (c *Config) IsValid() error {
	if c.MailDomain == "" {
		return fmt.Errorf("'Domain' not set but required")
	}
	if c.ListenTls {
		if c.TlsDomain == "" {
			return fmt.Errorf("please specifc a tls domain if you want to listen on TLS")
		}
		if err := c.Acme.IsValid(); err != nil {
			return fmt.Errorf("please specify a valid ACME config: %w", err)
		}
	}

	if err := c.Dkim.IsValid(); err != nil {
		return err
	}
	return nil
}

const defaultAcmeRenewalInterval = time.Hour * 24 * 30

func ConfigDefaults() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/config")

	viper.SetDefault("acme.caUrl", "https://acme-v02.api.letsencrypt.org/directory")

	viper.SetEnvPrefix("SMOLMAILER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	if err := BindStructToEnv(&Config{}, viper.GetViper()); err != nil {
		panic(fmt.Errorf("failed to bind config to environment: %w", err))
	}

	viper.SetDefault("listenAddr", "[::]:2525")
	viper.SetDefault("listenTls", false)
	viper.SetDefault("logLevel", utils.Must(slog.LevelInfo.MarshalText()))
	viper.SetDefault("queuePath", "/data/qeues")
	viper.SetDefault("userFile", "/config/users.yaml")
	viper.SetDefault("acme.automaticRenew", true)
	viper.SetDefault("acme.dir", "/data/acme")
	viper.SetDefault("acme.renewalInterval", defaultAcmeRenewalInterval)
	viper.SetDefault("acme.dns01.propagationTimeout", time.Minute*5)
}

func LoadConfig(logger *slog.Logger) (*Config, error) {
	ConfigDefaults()
	if err := viper.ReadInConfig(); err != nil && !errors.Is(err, &viper.ConfigFileNotFoundError{}) {
		logger.Warn("failed to read config", "err", err)
	}
	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		logger.Warn("failed to unmarshal config", "err", err)
		return nil, err
	}
	if err := cfg.IsValid(); err != nil {
		logger.Error("invalid/incomplete configuration", "err", err)
		return nil, err
	}
	return cfg, nil
}
