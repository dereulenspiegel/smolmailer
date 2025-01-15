package smolmailer

import (
	"github.com/dereulenspiegel/smolmailer/acme"
	"github.com/spf13/viper"
)

type UserConfig struct {
	Username string
	Password string // Securely hashed password
	FromAddr string
}

type Config struct {
	Domain          string
	ListenAddr      string
	SendAddr        string
	QueuePath       string
	Users           []*UserConfig
	AllowedIPRanges []string
	Acme            *acme.Config
}

func ConfigDefaults() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")
	viper.AddConfigPath("/.")

	viper.SetEnvPrefix("SMOLMAILER")
	viper.AutomaticEnv()
}
