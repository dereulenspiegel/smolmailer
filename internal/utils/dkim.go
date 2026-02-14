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

func ParseDkimKey(pemString string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM string")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
	}
}

func Signer(privKey crypto.PrivateKey) crypto.Signer {
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		panic(fmt.Errorf("can't assign private key of type %T as signer", privKey))
	}
	return signer
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

func dnsDkimKey(publicKey crypto.PublicKey) (string, string, error) {
	var pubkeyBytes []byte
	var keyType string
	var err error
	switch k := publicKey.(type) {
	case ed25519.PublicKey:
		keyType = "ed25519"
		pubkeyBytes = []byte(k)
	case *rsa.PublicKey:
		keyType = "rsa"
		pubkeyBytes, err = x509.MarshalPKIXPublicKey(k)
	case rsa.PublicKey:
		keyType = "rsa"
		pubkeyBytes, err = x509.MarshalPKIXPublicKey(&k)
	default:
		return "", "", fmt.Errorf("unsupported public key type: %T", k)
	}
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pubkeyBytes), keyType, nil
}

func DkimTxtRecordContent(privateKey crypto.PrivateKey) (string, error) {
	pubKey, err := pubKey(privateKey)
	if err != nil {
		return "", err
	}
	base64Key, keyType, err := dnsDkimKey(pubKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v=DKIM1;k=%s;h=%s;p=%s", keyType, "sha256", base64Key), nil
}

func DkimDomain(selector, domain string) string {
	return fmt.Sprintf("%s._domainkey.%s", selector, domain)
}
