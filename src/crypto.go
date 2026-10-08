package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"crypto/mldsa"
)

const deviceCredentialAAD = "relay-device-credential"

func oidcKeyID(key *ecdsa.PrivateKey) string {
	raw, _ := key.PublicKey.Bytes()
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func pubJWK(k *ecdsa.PublicKey) map[string]string {
	raw, _ := k.Bytes()

	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64.EncodeToString(raw[1:33]),
		"y":   b64.EncodeToString(raw[33:]),
	}
}

func parseJWK(v map[string]string) (*ecdsa.PublicKey, error) {
	if _, private := v["d"]; private {
		return nil, errors.New("private key material is not allowed")
	}

	if v["kty"] != "EC" || v["crv"] != "P-256" {
		return nil, errors.New("only P-256 EC keys are supported")
	}

	x, e := b64.DecodeString(v["x"])
	if e != nil {
		return nil, e
	}

	y, e := b64.DecodeString(v["y"])
	if e != nil {
		return nil, e
	}

	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("invalid P-256 coordinate length")
	}

	raw := append([]byte{4}, append(x, y...)...)
	key, e := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if e != nil {
		return nil, errors.New("invalid P-256 point")
	}

	return key, nil
}

func encodeMLDSAPublicKey(key *mldsa.PublicKey) string {
	return b64.EncodeToString(key.Bytes())
}

func parseMLDSAPublicKey(raw string) (*mldsa.PublicKey, error) {
	encoded, err := b64.DecodeString(raw)
	if err != nil || len(encoded) != mldsa.MLDSA65().PublicKeySize() {
		return nil, errors.New("invalid ML-DSA-65 public key")
	}

	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), encoded)
	if err != nil {
		return nil, errors.New("invalid ML-DSA-65 public key")
	}

	return key, nil
}

type credentialClaims struct {
	Issuer            string            `json:"iss"`
	Subject           string            `json:"sub"`
	Email             string            `json:"email"`
	EmailVerified     bool              `json:"email_verified"`
	Provider          string            `json:"provider_id"`
	UpstreamSub       string            `json:"upstream_subject"`
	UpstreamNamespace string            `json:"upstream_namespace"`
	IdentityName      string            `json:"identity_name,omitempty"`
	DeviceName        string            `json:"device_name"`
	JTI               string            `json:"jti"`
	IssuedAt          int64             `json:"iat"`
	ExpiresAt         int64             `json:"exp"`
	P256Key           map[string]string `json:"p256_key"`
	MLDSA65Key        string            `json:"mldsa65_key"`
}

func (s *Store) signCredential(d *Device, cfg Config) (string, error) {
	return s.signCredentialAt(d, cfg, time.Now())
}

func (s *Store) signCredentialAt(d *Device, cfg Config, issuedAt time.Time) (string, error) {
	if d == nil || d.PublicKey == nil || d.MLDSA65PublicKey == nil {
		return "", errors.New("device keys are incomplete")
	}

	claims := credentialClaims{
		Issuer:            cfg.Issuer,
		Subject:           d.Sub,
		Email:             d.Email,
		EmailVerified:     true,
		Provider:          d.Provider,
		UpstreamSub:       d.UpstreamSub,
		UpstreamNamespace: d.UpstreamNamespace,
		IdentityName:      d.IdentityName,
		DeviceName:        d.DeviceName,
		JTI:               d.JTI,
		IssuedAt:          issuedAt.Unix(),
		ExpiresAt:         issuedAt.Add(cfg.Lifetimes.Credential).Unix(),
		P256Key:           pubJWK(d.PublicKey),
		MLDSA65Key:        encodeMLDSAPublicKey(d.MLDSA65PublicKey),
	}

	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.deviceCredentialKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(deviceCredentialAAD))
	return "rdc." + b64.EncodeToString(nonce) + "." + b64.EncodeToString(ciphertext), nil
}

func (s *Store) verifyCredential(raw string, cfg Config) (*Device, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "rdc" {
		return nil, errors.New("invalid credential")
	}

	nonce, err := b64.DecodeString(parts[1])
	if err != nil || len(nonce) != 12 {
		return nil, errors.New("invalid credential")
	}

	ciphertext, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	block, err := aes.NewCipher(s.deviceCredentialKey)
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(deviceCredentialAAD))
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	var claims credentialClaims
	decoder := json.NewDecoder(strings.NewReader(string(plaintext)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return nil, errors.New("invalid credential")
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("invalid credential")
	}

	now := time.Now()
	if claims.Issuer != cfg.Issuer || claims.Subject == "" || claims.Email == "" || !claims.EmailVerified || claims.Provider == "" || claims.UpstreamSub == "" || claims.UpstreamNamespace == "" || claims.JTI == "" || claims.IssuedAt <= 0 || claims.IssuedAt > now.Add(deviceRequestClockSkew).Unix() || claims.ExpiresAt <= now.Unix() {
		return nil, errors.New("invalid credential")
	}

	if cfg.providerEnforcement && findProvider(cfg, claims.Provider) == nil {
		return nil, errors.New("provider is no longer configured")
	}

	p256, err := parseJWK(claims.P256Key)
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	mldsaKey, err := parseMLDSAPublicKey(claims.MLDSA65Key)
	if err != nil {
		return nil, errors.New("invalid credential")
	}

	return &Device{
		UpstreamNamespace: claims.UpstreamNamespace,
		Sub:               claims.Subject,
		Email:             claims.Email,
		Provider:          claims.Provider,
		UpstreamSub:       claims.UpstreamSub,
		JTI:               claims.JTI,
		DeviceName:        claims.DeviceName,
		IdentityName:      claims.IdentityName,
		PublicKey:         p256,
		MLDSA65PublicKey:  mldsaKey,
		Exp:               time.Unix(claims.ExpiresAt, 0),
	}, nil
}
