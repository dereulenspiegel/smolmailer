package smolmailer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/spf13/viper"
)

type UserConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"` // Securely hashed password
	FromAddr string `mapstructure:"from"`
}

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
	Domain          string        `mapstructure:"domain"`
	ListenAddr      string        `mapstructure:"listenAddr"`
	ListenTls       bool          `mapstructure:"listenTls"`
	SendAddr        string        `mapstructure:"sendAddr"`
	QueuePath       string        `mapstructure:"queuePath"`
	Users           []*UserConfig `mapstructure:"users"`
	AllowedIPRanges []string      `mapstructure:"allowedIPRanges"`
	Acme            *acme.Config  `mapstructure:"acme"`
	Dkim            *DkimOpts     `mapstructure:"dkim"`
}

func (c *Config) IsValid() error {
	if c.Domain == "" {
		return fmt.Errorf("'Domain' not set but required")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("no users configured")
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

	viper.SetDefault("domain", "")
	viper.SetDefault("listenAddr", "[:]:2525")
	viper.SetDefault("listenTls", false)
	viper.SetDefault("sendAddr", "")
	viper.SetDefault("queuePath", "/data/qeues")
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
