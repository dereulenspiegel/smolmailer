package smolmailer

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-crypt/crypt"
	yaml "gopkg.in/yaml.v3"
)

type UserService struct {
	users         map[string]*UserConfig
	passwdDecoder *crypt.Decoder
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

func NewUserService(userFilePath string) (*UserService, error) {

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
	}

	return us, nil
}

func (u *UserService) Authenticate(username, password string) error {
	if userCfg, exists := u.users[username]; !exists {
		return ErrUserNotFound
	} else {
		if userCfg.Username != username {
			return ErrInvalidCredentials
		}
		if digest, err := u.passwdDecoder.Decode(password); err != nil {
			return ErrInvalidCredentials
		} else {
			if !digest.Match(password) {
				return ErrInvalidCredentials
			}
		}
	}
	return nil
}

func (u *UserService) IsValidSender(username, from string) bool {
	if userCfg, exists := u.users[username]; exists {
		return userCfg.FromAddr == from
	}
	return false
}
