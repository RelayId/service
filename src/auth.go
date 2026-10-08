package main

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/mldsa"
)

type requestAuth struct {
	Device *Device
	Nonce  string
}

func (s *Store) authenticate(r *http.Request, cfg Config) (requestAuth, error) {
	parts := strings.SplitN(strings.TrimSpace(r.Header.Get("Authorization")), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "RelayDevice") || strings.TrimSpace(parts[1]) == "" {
		return requestAuth{}, errors.New("missing device credential")
	}
	raw := strings.TrimSpace(parts[1])
	if r.URL.RawQuery != "" {
		return requestAuth{}, errors.New("authenticated requests cannot use query parameters")
	}

	d, e := s.verifyCredential(raw, cfg)
	if e != nil {
		return requestAuth{}, e
	}

	ts := r.Header.Get("X-Relay-Timestamp")
	nonce := r.Header.Get("X-Relay-Nonce")
	if !validRequestNonce(nonce) {
		return requestAuth{}, errors.New("invalid nonce")
	}

	p256Signature, e := b64.DecodeString(r.Header.Get("X-Relay-P256-Signature"))
	if e != nil {
		return requestAuth{}, errors.New("bad signature")
	}

	mldsaSignature, e := b64.DecodeString(r.Header.Get("X-Relay-MLDSA65-Signature"))
	if e != nil || len(mldsaSignature) != mldsa.MLDSA65().SignatureSize() {
		return requestAuth{}, errors.New("bad signature")
	}

	if ts == "" || ts != strings.TrimSpace(ts) || strings.HasPrefix(ts, "+") {
		return requestAuth{}, errors.New("stale request")
	}

	for _, character := range ts {
		if character < '0' || character > '9' {
			return requestAuth{}, errors.New("stale request")
		}
	}

	sec, e := strconv.ParseInt(ts, 10, 64)
	now := time.Now().Unix()
	skew := int64(deviceRequestClockSkew / time.Second)
	if e != nil || sec < now-skew || sec > now+skew {
		return requestAuth{}, errors.New("stale request")
	}

	const maxSignedBody = 1 << 20
	body, e := io.ReadAll(io.LimitReader(r.Body, maxSignedBody+1))
	if e != nil {
		return requestAuth{}, errors.New("could not read request body")
	}

	if len(body) > maxSignedBody {
		return requestAuth{}, errors.New("request body too large")
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	canonical := deviceRequestCanonical(r.Method, r.URL.EscapedPath(), ts, nonce, body)
	if !ecdsa.VerifyASN1(d.PublicKey, sum([]byte(canonical)), p256Signature) {
		return requestAuth{}, errors.New("invalid request signature")
	}

	if mldsa.Verify(d.MLDSA65PublicKey, []byte(canonical), mldsaSignature, &mldsa.Options{}) != nil {
		return requestAuth{}, errors.New("invalid request signature")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.replayNonces[d.JTI+"\x00"+nonce]; ok {
		return requestAuth{}, errors.New("replayed request")
	}

	s.replayNonces[d.JTI+"\x00"+nonce] = time.Now().Add(deviceReplayNonceLifetime)
	return requestAuth{d, nonce}, nil
}

func deviceRequestCanonical(method, path, timestamp, nonce string, body []byte) string {
	return "relay-device-request\n" + method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + b64.EncodeToString(sum512(body))
}
