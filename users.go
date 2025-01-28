package smolmailer

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-crypt/crypt"
	yaml "gopkg.in/yaml.v3"
)

type UserConfig struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"` // Securely hashed password
	FromAddr string `mapstructure:"from" yaml:"from"`
}

type UserService struct {
	users         map[string]*UserConfig
	passwdDecoder *crypt.Decoder
	logger        *slog.Logger
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

func NewUserService(logger *slog.Logger, userFilePath string) (*UserService, error) {

	userFileBytes, err := os.ReadFile(userFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read users from %s: %w", userFilePath, err)
	}

	passwdDecoder, err := argon2Decoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create password decoder: %w", err)
	}

	us := &UserService{
		passwdDecoder: passwdDecoder,
		logger:        logger,
	}
	err = us.unmarshalConfig(userFileBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return us, nil
}

func (u *UserService) unmarshalConfig(userFileBytes []byte) error {
	userConfigs := []*UserConfig{}
	if err := yaml.Unmarshal(userFileBytes, &userConfigs); err != nil {
		return fmt.Errorf("failed to unmarshal user config: %w", err)
	}

	userMap := make(map[string]*UserConfig)
	for _, userCfg := range userConfigs {
		userMap[userCfg.Username] = userCfg
	}
	u.users = userMap
	return nil
}

func (u *UserService) Authenticate(username, password string) error {
	logger := u.logger.With("username", username)
	if userCfg, exists := u.users[username]; !exists {
		logger.Warn("user not found")
		return ErrInvalidCredentials
	} else {
		if userCfg.Username != username {
			logger.Warn("user name inconsistent")
			return ErrInvalidCredentials
		}
		if digest, err := u.passwdDecoder.Decode(userCfg.Password); err != nil {
			logger.Error("failed to decode password digest", "err", err)
			return ErrInvalidCredentials
		} else {
			if matched, err := digest.MatchAdvanced(password); !matched {
				logger.Warn("password does not match", "err", err)
				return ErrInvalidCredentials
			} else if err != nil {
				logger.Error("password matched, but we got an error, that shouldn't happen", "err", err)
				return ErrInvalidCredentials
			}
		}
	}
	logger.Debug("user authenticated successfully")
	return nil
}

func (u *UserService) IsValidSender(username, from string) bool {
	if userCfg, exists := u.users[username]; exists {
		return userCfg.FromAddr == from
	}
	return false
}
