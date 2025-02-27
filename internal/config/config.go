package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/dereulenspiegel/smolmailer/internal/utils"
	"github.com/spf13/viper"
)

type DkimOpts struct {
	Selector   string `mapstructure:"selector"`
	PrivateKey string `mapstructure:"privateKey"`
}

func (d *DkimOpts) IsValid() error {
	if d == nil {
		return errors.New("dkim options are not set")
	}
	if d.Selector == "" {
		return errors.New("DKIM selector must be set")
	}
	if d.PrivateKey == "" {
		return errors.New("DKIM Private Key must be set")
	}
	return nil
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
