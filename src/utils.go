package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

func isBase64URL(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validRequestNonce(value string) bool {
	if len(value) != 32 {
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 24 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func isPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}

	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}

		if strings.ContainsRune("-._~", character) {
			continue
		}

		return false
	}

	return true
}

var b64 = base64.RawURLEncoding

const mobileCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const demoMobileCode = "1234-5678"

func randomToken(n int) (string, error) {
	x := make([]byte, n)
	if _, err := rand.Read(x); err != nil {
		return "", err
	}

	return b64.EncodeToString(x), nil
}

func mobileCode(groups int) (string, error) {
	if groups < 2 || groups > 4 {
		return "", errors.New("mobile code group count is out of range")
	}

	raw := make([]byte, groups*4)
	for index := range raw {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(len(mobileCodeAlphabet))))
		if err != nil {
			return "", err
		}

		raw[index] = mobileCodeAlphabet[value.Int64()]
	}

	parts := make([]string, groups)
	for index := range parts {
		parts[index] = string(raw[index*4 : (index+1)*4])
	}

	return strings.Join(parts, "-"), nil
}

func mobileCodeGroupCount(config MobileCodeConfig) (int, error) {
	if config.Groups < 2 || config.Groups > 4 {
		return 0, errors.New("mobile code group count is invalid")
	}

	return config.Groups, nil
}

func normalizeMobileCode(value string) string {
	value = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	return value
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return b64.EncodeToString(h[:])
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, status int, msg string) {
	if msg == "" {
		msg = "Request failed."
	}

	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}

	jsonOut(w, status, struct {
		Status int    `json:"status"`
		Error  string `json:"error"`
	}{Status: status, Error: msg})
}

func apiData(w http.ResponseWriter, status int, value any) {
	jsonOut(w, status, struct {
		Status int `json:"status"`
		Data   any `json:"data"`
	}{Status: status, Data: value})
}

func readJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("missing body")
	}

	if !validMediaType(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("unsupported content type")
	}

	const maxJSONBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return err
	}

	if len(body) > maxJSONBody {
		return errors.New("request body too large")
	}

	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return errors.New("request body must be a JSON object")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}

	return nil
}

func validMediaType(raw, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)

	return err == nil && strings.EqualFold(mediaType, expected)
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func sum512(b []byte) []byte { h := sha512.Sum512(b); return h[:] }

func pkceS256(verifier string) string {
	return b64.EncodeToString(sum([]byte(verifier)))
}

func urlPath(value string) string { return url.PathEscape(value) }

func urlQuery(value string) string { return url.QueryEscape(value) }

func equalSecret(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}

	return result
}

func containsClaimScope(value any, required string) bool {
	scope, ok := value.(string)
	return ok && contains(strings.Fields(scope), required)
}
