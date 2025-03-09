package utils

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func ParseDkimKey(base64String string) (crypto.Signer, error) {
	// To be able to store this in env vars, we base64 encode it
	pemString, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode pem string: %w", err)
	}
	block, _ := pem.Decode(pemString)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM string")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return key.(ed25519.PrivateKey), err
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
	}
}

func pubKey(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privKey.(type) {
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *rsa.PrivateKey:
		return k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}

func dnsDkimKey(publicKey crypto.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to DER encode public key: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(pubkeyBytes), nil
}

func DkimTxtRecordContent(privateKey crypto.PrivateKey) (string, error) {
	pubKey, err := pubKey(privateKey)
	if err != nil {
		return "", err
	}
	base64Key, err := dnsDkimKey(pubKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v=DKIM1;k=%s;h=%s;p=%s", "ed25519", "sha256", base64Key), nil
}

func DkimDomain(selector, domain string) string {
	return fmt.Sprintf("%s._domainkey.%s", selector, domain)
}
