package smolmailer

import (
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
)

func argon2idHasher() (algorithm.Hash, error) {
	return argon2.New(argon2.WithProfileRFC9106Recommended(), argon2.WithIterations(2))
}

func argon2Decoder() (decoder *crypt.Decoder, err error) {
	decoder = crypt.NewDecoder()
	if err := argon2.RegisterDecoderArgon2id(decoder); err != nil {
		return nil, err
	}
	return decoder, nil
}

func encodePassword(password string, hasher algorithm.Hash) (string, error) {
	hash, err := hasher.Hash(password)
	if err != nil {
		return "", err
	}
	return algorithm.Digest.Encode(hash), nil
}

func MustEncodePassword(password string) string {
	hasher, err := argon2idHasher()
	if err != nil {
		panic(err)
	}
	encodedPasswd, err := encodePassword(password, hasher)
	if err != nil {
		panic(err)
	}
	return encodedPasswd
}
