package smolmailer

import (
	"fmt"
	"time"

	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/spf13/viper"
)

type UserConfig struct {
	Username string
	Password string // Securely hashed password
	FromAddr string
}

type DkimOpts struct {
	Selector   string
	PrivateKey string
}

type Config struct {
	Domain          string
	ListenAddr      string
	ListenTls       bool
	SendAddr        string
	QueuePath       string
	Users           []*UserConfig
	AllowedIPRanges []string
	Acme            *acme.Config
	Dkim            *DkimOpts
}

func (c *Config) IsValid() error {
	if c.Domain == "" {
		return fmt.Errorf("'Domain' not set but required")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("no users configured")
	}
	return nil
}

func ConfigDefaults() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/config")

	viper.SetDefault("Acme.AutomaticRenew", true)
	viper.SetDefault("Acme.Dir", "/data/acme")
	viper.SetDefault("Acme.RenewalInterval", time.Hour*24*30)
	viper.SetDefault("QueuePath", "/data/qeues")
	viper.SetDefault("ListenAddr", "[:]:2525")

	viper.SetEnvPrefix("SMOLMAILER")
	viper.AutomaticEnv()
}
