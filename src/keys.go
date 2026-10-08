package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

func configuredSigningKey(value, file string, development bool) (*ecdsa.PrivateKey, error) {
	if value != "" && file != "" {
		return nil, errors.New("signing key value and file are both configured")
	}

	if value != "" {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("signing key is not valid base64")
		}

		return parseSigningKey(raw)
	}

	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("signing key file is not PEM encoded")
		}

		return parseSigningKey(block.Bytes)
	}

	if !development {
		return nil, errors.New("signing key is required outside development mode")
	}

	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func parseSigningKey(raw []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, err
	}

	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be an ECDSA P-256 private key")
	}

	return privateKey, nil
}

func keygenJSON() (map[string]string, error) {
	o, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	op, err := x509.MarshalPKCS8PrivateKey(o)
	if err != nil {
		return nil, err
	}

	credentialKey := make([]byte, 32)
	if _, err := rand.Read(credentialKey); err != nil {
		return nil, err
	}

	return map[string]string{
		"oidc_signing_key_b64":      base64.StdEncoding.EncodeToString(op),
		"device_credential_key_b64": base64.StdEncoding.EncodeToString(credentialKey),
	}, nil
}

func configuredCredentialKey(value string, development bool) ([]byte, error) {
	if value == "" {
		if !development {
			return nil, errors.New("credential key is required outside development mode")
		}

		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	}

	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("credential key must be standard base64 for exactly 32 bytes")
	}

	return key, nil
}
