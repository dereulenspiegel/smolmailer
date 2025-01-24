package smolmailer

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-crypt/crypt"
	yaml "gopkg.in/yaml.v3"
)

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
	userConfigs := []*UserConfig{}
	if err := yaml.Unmarshal(userFileBytes, &userConfigs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user config %s: %w", userFilePath, err)
	}

	userMap := make(map[string]*UserConfig)
	for _, userCfg := range userConfigs {
		userMap[userCfg.Username] = userCfg
	}
	passwdDecoder, err := argon2Decoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create password decoder: %w", err)
	}

	us := &UserService{
		users:         userMap,
		passwdDecoder: passwdDecoder,
		logger:        logger,
	}

	return us, nil
}

func (u *UserService) Authenticate(username, password string) error {
	logger := u.logger.With("username", username)
	if userCfg, exists := u.users[username]; !exists {
		logger.Warn("user not found")
		return ErrUserNotFound
	} else {
		if userCfg.Username != username {
			logger.Warn("user name inconsistent")
			return ErrInvalidCredentials
		}
		if digest, err := u.passwdDecoder.Decode(password); err != nil {
			logger.Error("failed to decode password digest", "err", err)
			return ErrInvalidCredentials
		} else {
			if !digest.Match(password) {
				logger.Warn("password does not match")
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
