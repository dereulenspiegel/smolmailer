package smolmailer

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/spf13/viper"
)

type DkimOpts struct {
	Selector   string `mapstructure:"selector"`
	PrivateKey string `mapstructure:"privateKey"`
}

func (d *DkimOpts) IsValid() error {
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
	if c.ListenTls && (c.TlsDomain == "" || c.Acme == nil) {
		return fmt.Errorf("When listening to TLS you need to specify the TLS Domain and a valid acme config")
	}

	if err := c.Acme.IsValid(); err != nil {
		return err
	}

	if err := c.Dkim.IsValid(); err != nil {
		return err
	}
	return nil
}

func ConfigDefaults() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/config")

	viper.SetDefault("mailDomain", "")
	viper.SetDefault("listenAddr", "[::]:2525")
	viper.SetDefault("listenTls", false)
	viper.SetDefault("logLevel", must(slog.LevelInfo.MarshalText()))
	viper.SetDefault("sendAddr", "")
	viper.SetDefault("queuePath", "/data/qeues")
	viper.SetDefault("userFile", "/config/users.yaml")
	viper.SetDefault("dkim.selector", "")
	viper.SetDefault("dkim.privateKey", "")
	viper.SetDefault("acme.automaticRenew", true)
	viper.SetDefault("acme.dir", "/data/acme")
	viper.SetDefault("acme.renewalInterval", time.Hour*24*30)
	viper.SetDefault("acme.email", "")
	viper.SetDefault("acme.caUrl", "https://acme-v02.api.letsencrypt.org/directory")
	viper.SetDefault("acme.dns01ProviderName", "")

	viper.SetEnvPrefix("SMOLMAILER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}
