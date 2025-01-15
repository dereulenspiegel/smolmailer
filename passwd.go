package smolmailer

import (
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
)

func pbkdf2OnlyDecoder() (decoder *crypt.Decoder, err error) {
	decoder = crypt.NewDecoder()
	if err := pbkdf2.RegisterDecoderSHA512(decoder); err != nil {
		return nil, err
	}
	return decoder, nil
}

func pbkdf2OnlyHasher() (algorithm.Hash, error) {
	return pbkdf2.NewSHA512()
}

func encodePassword(password string, hasher algorithm.Hash) (string, error) {
	hash, err := hasher.Hash(password)
	if err != nil {
		return "", err
	}
	return algorithm.Digest.Encode(hash), nil
}

func MustEncodePassword(password string) string {
	hasher, err := pbkdf2OnlyHasher()
	if err != nil {
		panic(err)
	}
	encodedPasswd, err := encodePassword(password, hasher)
	if err != nil {
		panic(err)
	}
	return encodedPasswd
}
