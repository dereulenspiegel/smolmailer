package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/dereulenspiegel/smolmailer/internal/utils"
	"github.com/spf13/viper"
)

type DkimPrivateKeys struct {
	Ed25519 string `mapstructure:"ed25519"`
	RSA     string `mapstructure:"rsa"`
}

type DkimOpts struct {
	Selector    string           `mapstructure:"selector"`
	PrivateKeys *DkimPrivateKeys `mapstructure:"privateKeys"`
	//PrivateKey string `mapstructure:"privateKey"`
}

func (d *DkimOpts) IsValid() error {
	if d == nil {
		return errors.New("dkim options are not set")
	}
	if d.Selector == "" {
		return errors.New("DKIM selector must be set")
	}
	if d.PrivateKeys == nil {
		return errors.New("DKIM private keys must be set")
	}
	if d.PrivateKeys.Ed25519 == "" {
		return errors.New("Ed25519 DKIM Private Key must be set")
	}
	// Make RSA optional for now
	// if d.PrivateKeys.RSA == "" {
	// 	return errors.New("RSA DKIM Private Key must be set")
	// }
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
