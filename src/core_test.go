package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/mldsa"
	"github.com/JLugagne/egauth/oauth"
	"github.com/golang-jwt/jwt/v5"
)

func testMLDSAKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func signTestRequest(t *testing.T, request *http.Request, p256Key *ecdsa.PrivateKey, mldsaKey *mldsa.PrivateKey) {
	t.Helper()

	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}

	request.Body = io.NopCloser(bytes.NewReader(body))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomToken(24)
	if err != nil {
		t.Fatal(err)
	}

	canonical := deviceRequestCanonical(request.Method, request.URL.EscapedPath(), timestamp, nonce, body)
	p256Signature, err := ecdsa.SignASN1(rand.Reader, p256Key, sum([]byte(canonical)))
	if err != nil {
		t.Fatal(err)
	}

	mldsaSignature, err := mldsaKey.Sign(nil, []byte(canonical), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("X-Relay-Timestamp", timestamp)
	request.Header.Set("X-Relay-Nonce", nonce)
	request.Header.Set("X-Relay-P256-Signature", b64.EncodeToString(p256Signature))
	request.Header.Set("X-Relay-MLDSA65-Signature", b64.EncodeToString(mldsaSignature))
}

func TestCredentialPreservesUpstreamNamespace(t *testing.T) {
	cfg := defaults()
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	d := &Device{UpstreamNamespace: "https://accounts.google.com", Sub: "stable", Email: "person@example.com", Provider: "test", UpstreamSub: "upstream", JTI: "jti", PublicKey: &key.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()}
	raw, err := s.signCredential(d, cfg)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.verifyCredential(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}

	gotBytes, _ := got.PublicKey.Bytes()
	wantBytes, _ := key.PublicKey.Bytes()
	if got.UpstreamNamespace != d.UpstreamNamespace || got.Email != d.Email || got.Sub != d.Sub || !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("credential mismatch: %#v", got)
	}
}

func TestDeviceCredentialAuthenticatesAndRejectsTampering(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)
	device := &Device{UpstreamNamespace: "https://issuer.example", Sub: "stable", Email: "person@example.com", Provider: "test", UpstreamSub: "upstream", JTI: "jti", PublicKey: &p256Key.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}

	first, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "rdc.") {
		t.Fatal("device credentials did not use randomized rdc format")
	}

	if _, err := store.verifyCredential(first, cfg); err != nil {
		t.Fatal(err)
	}

	productionCfg := cfg
	productionCfg.Development = false
	productionCfg.providerEnforcement = true
	productionCfg.OAuth2.Providers = []Provider{{ID: "test"}}
	if _, err := store.verifyCredential(first, productionCfg); err != nil {
		t.Fatalf("configured provider credential was rejected: %v", err)
	}
	productionCfg.OAuth2.Providers = nil
	if _, err := store.verifyCredential(first, productionCfg); err == nil {
		t.Fatal("credential remained valid after its provider was removed")
	}

	credentialParts := strings.Split(first, ".")
	tamperedCiphertext, err := b64.DecodeString(credentialParts[2])
	if err != nil {
		t.Fatal(err)
	}
	tamperedCiphertext[0] ^= 1
	tampered := credentialParts[0] + "." + credentialParts[1] + "." + b64.EncodeToString(tamperedCiphertext)
	if _, err := store.verifyCredential(tampered, cfg); err == nil {
		t.Fatal("tampered credential was accepted")
	}

	other, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.verifyCredential(first, cfg); err == nil {
		t.Fatal("credential accepted with a different AES-GCM key")
	}

	if _, err := store.verifyCredential("eyJhbGciOiJFUzI1NiJ9.invalid.invalid", cfg); err == nil {
		t.Fatal("v1 credential was accepted")
	}
}

func TestHybridRequestHeaderBudget(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://" + strings.Repeat("i", maxIssuerBytes-len("https://"))
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)
	jti, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	device := &Device{UpstreamNamespace: "https://" + strings.Repeat("u", maxIssuerBytes-len("https://")), Sub: strings.Repeat("s", 256), Email: strings.Repeat("e", 256), Provider: strings.Repeat("p", 64), UpstreamSub: strings.Repeat("u", 256), JTI: jti, IdentityName: strings.Repeat("i", 256), DeviceName: strings.Repeat("d", 256), PublicKey: &p256Key.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}
	credential, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{}`)
	request := httptest.NewRequest(http.MethodPost, "/api/codes", bytes.NewReader(body))
	signTestRequest(t, request, p256Key, pqKey)
	headerBytes := len("Authorization: RelayDevice "+credential) + len("X-Relay-Timestamp: "+request.Header.Get("X-Relay-Timestamp")) + len("X-Relay-Nonce: "+request.Header.Get("X-Relay-Nonce")) + len("X-Relay-P256-Signature: "+request.Header.Get("X-Relay-P256-Signature")) + len("X-Relay-MLDSA65-Signature: "+request.Header.Get("X-Relay-MLDSA65-Signature"))
	if len("RelayDevice "+credential) >= 8<<10 {
		t.Fatalf("authorization header exceeds 8 KiB: %d", len("RelayDevice "+credential))
	}
	if headerBytes >= 32<<10 {
		t.Fatalf("hybrid request headers exceed 32 KiB: %d", headerBytes)
	}
	t.Logf("authorization header bytes=%d total Relay authentication header bytes=%d", len("RelayDevice "+credential), headerBytes)
}

func TestHybridAuthenticationRejectsIncompleteOrMutatedRequests(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)
	otherP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPQ := testMLDSAKey(t)
	credential, err := store.signCredential(&Device{Sub: "device", Email: "person@example.com", Provider: "google", UpstreamNamespace: "https://accounts.google.com", UpstreamSub: "subject", JTI: "hybrid-negative", PublicKey: &p256Key.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "missing P-256 signature", mutate: func(request *http.Request) { request.Header.Del("X-Relay-P256-Signature") }},
		{name: "missing ML-DSA signature", mutate: func(request *http.Request) { request.Header.Del("X-Relay-MLDSA65-Signature") }},
		{name: "invalid ML-DSA signature", mutate: func(request *http.Request) {
			request.Header.Set("X-Relay-MLDSA65-Signature", b64.EncodeToString(make([]byte, mldsa.MLDSA65().SignatureSize())))
		}},
		{name: "invalid P-256 signature", mutate: func(request *http.Request) {
			request.Header.Set("X-Relay-P256-Signature", b64.EncodeToString([]byte("invalid")))
		}},
		{name: "P-256 signature from another key", mutate: func(request *http.Request) { signTestRequest(t, request, otherP256, pqKey) }},
		{name: "ML-DSA signature from another key", mutate: func(request *http.Request) { signTestRequest(t, request, p256Key, otherPQ) }},
		{name: "body changed after signing", mutate: func(request *http.Request) { request.Body = io.NopCloser(strings.NewReader(`{"changed":true}`)) }},
		{name: "path changed after signing", mutate: func(request *http.Request) { request.URL.Path = "/api/other" }},
		{name: "query string present", mutate: func(request *http.Request) { request.URL.RawQuery = "unexpected=1" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/codes", strings.NewReader(`{}`))
			request.Header.Set("Authorization", "RelayDevice "+credential)
			signTestRequest(t, request, p256Key, pqKey)
			test.mutate(request)
			if _, err := store.authenticate(request, cfg); err == nil {
				t.Fatal("mutated request was accepted")
			}
		})
	}

	replay := httptest.NewRequest(http.MethodPost, "/api/codes", strings.NewReader(`{}`))
	replay.Header.Set("Authorization", "RelayDevice "+credential)
	signTestRequest(t, replay, p256Key, pqKey)
	if _, err := store.authenticate(replay, cfg); err != nil {
		t.Fatalf("valid hybrid request was rejected: %v", err)
	}
	replay.Body = io.NopCloser(strings.NewReader(`{}`))
	if _, err := store.authenticate(replay, cfg); err == nil {
		t.Fatal("replayed request was accepted")
	}
}

func TestClientSigningCanonicalization(t *testing.T) {
	fixtureDir := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)

	rawBody := "{}"
	digest := b64.EncodeToString(sum512([]byte(rawBody)))
	nonce := b64.EncodeToString(bytes.Repeat([]byte{0}, 24))
	canonical := "relay-device-request\nPOST\n/api/codes\n1700000000\n" + nonce + "\n" + digest
	requestSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, sum([]byte(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	mldsaSignature, err := pqKey.Sign(nil, []byte(canonical), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	requestFixture := map[string]any{
		"method": "POST", "path": "/api/codes", "timestamp": "1700000000", "nonce": nonce,
		"raw_body": rawBody, "body_sha512": digest, "canonical": canonical,
		"public_jwk": pubJWK(&privateKey.PublicKey), "signature_p256": b64.EncodeToString(requestSignature), "signature_mldsa65": b64.EncodeToString(mldsaSignature),
	}

	enrollmentPayload := "relay-enrollment\nexample@example.com\n1700000000"
	enrollmentSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, sum([]byte(enrollmentPayload)))
	if err != nil {
		t.Fatal(err)
	}
	enrollmentMLDSASignature, err := pqKey.Sign(nil, []byte(enrollmentPayload), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	enrollmentFixture := map[string]any{
		"signing_payload":   enrollmentPayload,
		"public_jwk":        pubJWK(&privateKey.PublicKey),
		"signature_p256":    b64.EncodeToString(enrollmentSignature),
		"signature_mldsa65": b64.EncodeToString(enrollmentMLDSASignature),
	}

	writeFixture := func(name string, value any) {
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(filepath.Join(fixtureDir, name), raw, 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	writeFixture("request-signing.json", requestFixture)
	writeFixture("enrollment-signing.json", enrollmentFixture)

	var request struct {
		Method         string            `json:"method"`
		Path           string            `json:"path"`
		Timestamp      string            `json:"timestamp"`
		Nonce          string            `json:"nonce"`
		RawBody        string            `json:"raw_body"`
		Digest         string            `json:"body_sha512"`
		Canonical      string            `json:"canonical"`
		PublicJWK      map[string]string `json:"public_jwk"`
		Signature      string            `json:"signature_p256"`
		MLDSASignature string            `json:"signature_mldsa65"`
	}

	readFixture(t, filepath.Join(fixtureDir, "request-signing.json"), &request)

	if !validRequestNonce(request.Nonce) || b64.EncodeToString(sum512([]byte(request.RawBody))) != request.Digest {
		t.Fatal("request fixture digest or nonce is invalid")
	}

	canonical = "relay-device-request\n" + request.Method + "\n" + request.Path + "\n" + request.Timestamp + "\n" + request.Nonce + "\n" + request.Digest
	if canonical != request.Canonical {
		t.Fatal("request fixture canonical bytes changed")
	}

	publicKey, err := parseJWK(request.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := b64.DecodeString(request.Signature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, sum([]byte(request.Canonical)), signature) {
		t.Fatal("request fixture signature is invalid")
	}

	mldsaSignature, err = b64.DecodeString(request.MLDSASignature)
	if err != nil || mldsa.Verify(pqKey.PublicKey(), []byte(request.Canonical), mldsaSignature, &mldsa.Options{}) != nil {
		t.Fatal("ML-DSA request fixture signature is invalid")
	}

	var enrollment struct {
		Payload        string            `json:"signing_payload"`
		PublicJWK      map[string]string `json:"public_jwk"`
		Signature      string            `json:"signature_p256"`
		MLDSASignature string            `json:"signature_mldsa65"`
	}

	readFixture(t, filepath.Join(fixtureDir, "enrollment-signing.json"), &enrollment)
	publicKey, err = parseJWK(enrollment.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}

	signature, err = b64.DecodeString(enrollment.Signature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, sum([]byte(enrollment.Payload)), signature) {
		t.Fatal("enrollment fixture signature is invalid")
	}

	mldsaSignature, err = b64.DecodeString(enrollment.MLDSASignature)
	if err != nil || mldsa.Verify(pqKey.PublicKey(), []byte(enrollment.Payload), mldsaSignature, &mldsa.Options{}) != nil {
		t.Fatal("ML-DSA enrollment fixture signature is invalid")
	}
}

func TestGenericOIDCOutageDoesNotPreventRelayStartup(t *testing.T) {
	available := false
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" || !available {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
		})
	}))

	defer server.Close()

	cfg := defaults()
	cfg.OAuth2.Providers = []Provider{{ID: "local-oidc", Name: "Local OIDC", Provider: "oidc", Issuer: server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost:3000/oauth2/local-oidc/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatalf("OIDC outage prevented Relay startup: %v", err)
	}

	response := httptest.NewRecorder()
	store.routes(cfg).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("downstream status failed during upstream outage: %d", response.Code)
	}
}

func TestGenericOIDCEnrollmentRetriesAfterProviderRecovery(t *testing.T) {
	available := false
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" || !available {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
		})
	}))

	defer server.Close()

	cfg := defaults()
	cfg.OAuth2.Providers = []Provider{{ID: "local-oidc", Name: "Local OIDC", Provider: "oidc", Issuer: server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost:3000/oauth2/local-oidc/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.enrollmentState["enrollment"] = &Enrollment{ID: "enrollment", State: "pending", Expires: time.Now().Add(time.Minute)}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/enrollments/enrollment/oauth2", bytes.NewBufferString(`{"provider_id":"local-oidc"}`))
	request.Header.Set("Content-Type", "application/json")
	store.routes(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("OIDC outage returned %d, want 503: %s", response.Code, response.Body.String())
	}

	available = true
	authorizationURL, _, err := store.beginOAuth2Enrollment(context.Background(), cfg, "enrollment", "local-oidc", time.Now())
	if err != nil || authorizationURL == "" {
		t.Fatalf("OIDC enrollment did not retry after recovery: url=%q err=%v", authorizationURL, err)
	}
}

func TestOAuthCallbackAcceptsMatchingIssuer(t *testing.T) {
	provider := oauth.New("oidc", "client", "secret", "https://issuer.example.com/authorize", "https://issuer.example.com/token", nil, genericUserInfo("https://issuer.example.com/userinfo"))
	if !validOAuthResponseIssuer(provider, url.Values{"iss": {"https://issuer.example.com/"}}) {
		t.Fatal("matching authorization-response issuer was rejected")
	}
}

func TestOAuthCallbackRejectsWrongIssuer(t *testing.T) {
	provider := oauth.New("oidc", "client", "secret", "https://issuer.example.com/authorize", "https://issuer.example.com/token", nil, genericUserInfo("https://issuer.example.com/userinfo"))
	if validOAuthResponseIssuer(provider, url.Values{"iss": {"https://wrong.example.com"}}) {
		t.Fatal("wrong authorization-response issuer was accepted")
	}
}

func TestOAuthCallbackRejectsDuplicateIssuer(t *testing.T) {
	provider := oauth.New("oidc", "client", "secret", "https://issuer.example.com/authorize", "https://issuer.example.com/token", nil, genericUserInfo("https://issuer.example.com/userinfo"))
	if validOAuthResponseIssuer(provider, url.Values{"iss": {"https://issuer.example.com", "https://issuer.example.com"}}) {
		t.Fatal("duplicate authorization-response issuer was accepted")
	}
}

func TestOAuthCallbackAllowsAbsentIssuer(t *testing.T) {
	provider := oauth.New("oauth", "client", "secret", "https://issuer.example.com/authorize", "https://issuer.example.com/token", nil, genericUserInfo("https://issuer.example.com/userinfo"))
	if !validOAuthResponseIssuer(provider, url.Values{}) {
		t.Fatal("authorization response without optional issuer was rejected")
	}
}

func TestOIDCProviderDiscoveryIsPerProvider(t *testing.T) {
	aStarted := make(chan struct{})
	releaseA := make(chan struct{})

	var aServer *httptest.Server
	aServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			select {
			case <-aStarted:
			default:
				close(aStarted)
			}
			select {
			case <-releaseA:
			case <-r.Context().Done():
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": aServer.URL, "authorization_endpoint": aServer.URL + "/authorize", "token_endpoint": aServer.URL + "/token"})
			return
		}
		http.NotFound(w, r)
	}))

	defer aServer.Close()

	var bServer *httptest.Server
	bServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": bServer.URL, "authorization_endpoint": bServer.URL + "/authorize", "token_endpoint": bServer.URL + "/token"})
			return
		}

		http.NotFound(w, r)
	}))

	defer bServer.Close()

	cfg := defaults()
	cfg.OAuth2.Providers = []Provider{
		{ID: "slow", Name: "Slow", Provider: "oidc", Issuer: aServer.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost:3000/oauth2/slow/callback"},
		{ID: "fast", Name: "Fast", Provider: "oidc", Issuer: bServer.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost:3000/oauth2/fast/callback"},
	}

	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.enrollmentState["slow-enrollment"] = &Enrollment{ID: "slow-enrollment", State: "pending", Expires: time.Now().Add(time.Minute)}
	store.enrollmentState["fast-enrollment"] = &Enrollment{ID: "fast-enrollment", State: "pending", Expires: time.Now().Add(time.Minute)}

	slowDone := make(chan error, 1)
	go func() {
		_, _, startErr := store.beginOAuth2Enrollment(context.Background(), cfg, "slow-enrollment", "slow", time.Now())
		slowDone <- startErr
	}()

	<-aStarted

	fastContext, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, _, err := store.beginOAuth2Enrollment(fastContext, cfg, "fast-enrollment", "fast", time.Now()); err != nil {
		close(releaseA)
		t.Fatalf("healthy provider was serialized behind slow discovery: %v", err)
	}

	close(releaseA)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow provider did not finish after release: %v", err)
	}
}

func TestOIDCProviderDiscoveryIsCached(t *testing.T) {
	var calls int
	var callsMu sync.Mutex
	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			callsMu.Lock()
			calls++
			callsMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token"})
			return
		}
		http.NotFound(w, r)
	}))

	defer server.Close()

	cfg := defaults()
	cfg.OAuth2.Providers = []Provider{{ID: "cached", Name: "Cached", Provider: "oidc", Issuer: server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost:3000/oauth2/cached/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.enrollmentState["first"] = &Enrollment{ID: "first", State: "pending", Expires: time.Now().Add(time.Minute)}
	store.enrollmentState["second"] = &Enrollment{ID: "second", State: "pending", Expires: time.Now().Add(time.Minute)}
	for _, id := range []string{"first", "second"} {
		if _, _, err := store.beginOAuth2Enrollment(context.Background(), cfg, id, "cached", time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("OIDC discovery was not cached: %d calls", calls)
	}
}

func TestOAuthCallbackRejectsMalformedIssuer(t *testing.T) {
	provider := oauth.New("oidc", "client", "secret", "https://issuer.example.com/authorize", "https://issuer.example.com/token", nil, genericUserInfo("https://issuer.example.com/userinfo"))
	for _, issuer := range []string{"not a URI", "https://issuer.example.com/unexpected-path"} {
		if validOAuthResponseIssuer(provider, url.Values{"iss": {issuer}}) {
			t.Fatalf("malformed authorization-response issuer was accepted: %q", issuer)
		}
	}
}

func readFixture(t *testing.T, name string, target any) {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func TestDifferentUpstreamNamespacesProduceDifferentSubjects(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	devices := []*Device{
		{UpstreamNamespace: "https://accounts.google.com", Sub: "google", Email: "person@example.com", Provider: "google", UpstreamSub: "123", JTI: "google-jti", PublicKey: &key.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()},
		{UpstreamNamespace: "https://login.example.com", Sub: "company", Email: "person@example.com", Provider: "company", UpstreamSub: "123", JTI: "company-jti", PublicKey: &key.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()},
	}

	subjects := make([]string, 0, len(devices))
	for _, device := range devices {
		credential, err := store.signCredential(device, cfg)
		if err != nil {
			t.Fatal(err)
		}

		verified, err := store.verifyCredential(credential, cfg)
		if err != nil {
			t.Fatal(err)
		}

		subjects = append(subjects, hash("relay/subject\n"+verified.UpstreamNamespace+"\n"+verified.UpstreamSub))
	}

	if subjects[0] == subjects[1] {
		t.Fatal("different upstream issuers produced the same subject")
	}
}

func TestCanonicalDeviceRequestRejectsStaleTimestamp(t *testing.T) {
	cfg := defaults()
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)

	device := &Device{Sub: "device", Email: "person@example.com", Provider: "provider", UpstreamNamespace: "https://issuer", UpstreamSub: "subject", JTI: "jti", PublicKey: &deviceKey.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}
	credential, err := s.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{}`)
	timestamp := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	nonce := b64.EncodeToString(bytes.Repeat([]byte{0}, 24))
	canonical := "relay-device-request\nPOST\n/api/codes\n" + timestamp + "\n" + nonce + "\n" + b64.EncodeToString(sum512(body))
	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(canonical)))
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/api/codes", bytes.NewReader(body))
	r.Header.Set("Authorization", "RelayDevice "+credential)
	r.Header.Set("X-Relay-Timestamp", timestamp)
	r.Header.Set("X-Relay-Nonce", nonce)
	r.Header.Set("X-Relay-P256-Signature", b64.EncodeToString(signature))
	r.Header.Set("X-Relay-MLDSA65-Signature", b64.EncodeToString(make([]byte, mldsa.MLDSA65().SignatureSize())))
	if _, err := s.authenticate(r, cfg); err == nil || err.Error() != "stale request" {
		t.Fatalf("expected stale request, got %v", err)
	}
}

func TestSignedRequestBodyLimitRejectsOversizeBody(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	device := &Device{Sub: "device", Email: "person@example.com", Provider: "provider", UpstreamNamespace: "https://issuer", UpstreamSub: "subject", JTI: "jti", PublicKey: &deviceKey.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()}
	credential, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.Repeat([]byte("x"), (1<<20)+1)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := b64.EncodeToString(bytes.Repeat([]byte{0}, 24))
	canonical := "relay-device-request\nPOST\n/api/codes\n" + timestamp + "\n" + nonce + "\n" + b64.EncodeToString(sum512(body))
	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(canonical)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/codes", bytes.NewReader(body))
	request.Header.Set("Authorization", "RelayDevice "+credential)
	request.Header.Set("X-Relay-Timestamp", timestamp)
	request.Header.Set("X-Relay-Nonce", nonce)
	request.Header.Set("X-Relay-P256-Signature", b64.EncodeToString(signature))
	request.Header.Set("X-Relay-MLDSA65-Signature", b64.EncodeToString(make([]byte, mldsa.MLDSA65().SignatureSize())))
	if _, err := store.authenticate(request, cfg); err == nil || err.Error() != "request body too large" {
		t.Fatalf("oversize signed body was rejected incorrectly: %v", err)
	}
}

func TestDeviceRequestRejectsInvalidNonceAndQueryString(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	credential, err := store.signCredential(&Device{Sub: "device", Email: "person@example.com", Provider: "google", UpstreamNamespace: "relay:oauth2:google", UpstreamSub: "subject", JTI: "nonce-test", PublicKey: &key.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	queryRequest := httptest.NewRequest(http.MethodPost, "/api/codes?unexpected=1", strings.NewReader("{}"))
	queryRequest.Header.Set("Authorization", "RelayDevice "+credential)
	if _, err := store.authenticate(queryRequest, cfg); err == nil || err.Error() != "authenticated requests cannot use query parameters" {
		t.Fatalf("query string was not rejected: %v", err)
	}

	badNonce := httptest.NewRequest(http.MethodPost, "/api/codes", strings.NewReader("{}"))
	badNonce.Header.Set("Authorization", "RelayDevice "+credential)
	badNonce.Header.Set("X-Relay-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	badNonce.Header.Set("X-Relay-Nonce", "not-a-valid-nonce")
	if _, err := store.authenticate(badNonce, cfg); err == nil || err.Error() != "invalid nonce" {
		t.Fatalf("invalid nonce was not rejected: %v", err)
	}
}

func TestIssuerAndProviderConfigurationValidation(t *testing.T) {
	valid := "issuer: https://relay.example.com/\noidc:\n  clients:\n    - id: client\n      secret: " + strings.Repeat("s", 32) + "\n      redirect_uris: [https://client.example/callback]\noauth2:\n  providers:\n    - id: company-login\n      name: Company\n      provider: oidc\n      issuer: https://id.example\n      client_id: client\n      client_secret: " + strings.Repeat("p", 32) + "\n"
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(file)
	if err != nil || cfg.Issuer != "https://relay.example.com" {
		t.Fatalf("valid issuer was not normalized: cfg=%#v err=%v", cfg, err)
	}

	for _, invalid := range []string{"issuer: https://relay.example.com/path\n", "issuer: https://relay.example.com/?bad=1\n", "issuer: https://relay.example.com/#fragment\n"} {
		badFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(badFile, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}

		if _, err := loadConfig(badFile); err == nil {
			t.Fatalf("invalid issuer accepted: %s", invalid)
		}
	}

	tooLong := "https://" + strings.Repeat("a", maxIssuerBytes)
	tooLongFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tooLongFile, []byte("issuer: "+tooLong+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(tooLongFile); err == nil {
		t.Fatal("oversized relay issuer accepted")
	}

	tooLongProvider := strings.Replace(valid, "https://id.example", "https://"+strings.Repeat("b", maxIssuerBytes), 1)
	tooLongProviderFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tooLongProviderFile, []byte(tooLongProvider), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(tooLongProviderFile); err == nil {
		t.Fatal("oversized OIDC provider issuer accepted")
	}

	unsafeProvider := strings.Replace(valid, "company-login", "company/login", 1)
	unsafeFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(unsafeFile, []byte(unsafeProvider), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(unsafeFile); err == nil {
		t.Fatal("unsafe provider ID accepted")
	}

	for _, preset := range []string{"unknown", "openid-connect"} {
		unsupported := strings.Replace(valid, "provider: oidc", "provider: "+preset, 1)
		unsupportedFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(unsupportedFile, []byte(unsupported), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(unsupportedFile); err == nil {
			t.Fatalf("unknown provider preset accepted: %s", preset)
		}
	}
}

func TestOIDCRedirectURIRequiresHTTPSInProduction(t *testing.T) {
	base := "issuer: https://relay.example.com\noidc:\n  clients:\n    - id: client\n      secret: " + strings.Repeat("s", 32) + "\n      redirect_uris: [%s]\n"
	cases := []struct {
		name        string
		redirect    string
		development bool
		valid       bool
	}{
		{name: "https", redirect: "https://client.example/callback", valid: true},
		{name: "javascript", redirect: "javascript://client.example/callback", valid: false},
		{name: "ftp", redirect: "ftp://client.example/callback", valid: false},
		{name: "production http", redirect: "http://localhost:8080/callback", valid: false},
		{name: "development localhost http", redirect: "http://localhost:8080/callback", development: true, valid: true},
		{name: "development remote http", redirect: "http://client.example/callback", development: true, valid: false},
		{name: "userinfo", redirect: "https://user:pass@client.example/callback", valid: false},
		{name: "fragment", redirect: "https://client.example/callback#fragment", valid: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			raw := fmt.Sprintf("development: %t\n%s", testCase.development, fmt.Sprintf(base, testCase.redirect))
			file := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}

			_, err := loadConfig(file)
			if (err == nil) != testCase.valid {
				t.Fatalf("redirect validation result=%v, want valid=%v: %v", err == nil, testCase.valid, err)
			}
		})
	}
}

func TestIssuerRejectsUserInfo(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("issuer: https://user:password@relay.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(file); err == nil {
		t.Fatal("issuer userinfo was accepted")
	}
}

func TestLifetimesMustBePositive(t *testing.T) {
	fields := []string{"login", "enrollment", "code", "credential"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			raw := "issuer: https://relay.example.com\nlifetimes:\n  " + field + ": 0s\n"
			if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}

			if _, err := loadConfig(file); err == nil {
				t.Fatal("non-positive duration was accepted")
			}
		})
	}
}

func TestLifetimesRejectObsoleteConfiguration(t *testing.T) {
	for _, raw := range []string{
		"issuer: https://relay.example.com\ndurations:\n  login: 5m\n",
		"issuer: https://relay.example.com\nlifetimes:\n  login: 5m\n  auth_code: 1m\n",
		"issuer: https://relay.example.com\nlifetimes:\n  login: 5m\n  access_token: 5m\n",
		"issuer: https://relay.example.com\nlifetimes:\n  login: 5m\n  device_skew: 45s\n",
		"issuer: https://relay.example.com\nlifetimes:\n  login: 5m\n  replay_nonce_ttl: 2m\n",
	} {
		file := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}

		if _, err := loadConfig(file); err == nil {
			t.Fatalf("obsolete configuration was accepted: %s", raw)
		}
	}
}

func TestFriendlyLifetimeSyntax(t *testing.T) {
	for input, expected := range map[string]time.Duration{"45s": 45 * time.Second, "5m": 5 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour, "1w": 7 * 24 * time.Hour, "12w": 84 * 24 * time.Hour} {
		value, err := parseFriendlyDuration(input)
		if err != nil || value != expected {
			t.Fatalf("parseFriendlyDuration(%q) = %v, %v; want %v", input, value, err, expected)
		}
	}

	for _, input := range []string{"0d", "1.5d", "1month", "1year"} {
		if _, err := parseFriendlyDuration(input); err == nil {
			t.Fatalf("ambiguous or invalid duration accepted: %q", input)
		}
	}
}

func TestDevelopmentLoopbackURLRules(t *testing.T) {
	for _, raw := range []string{"http://[::1]:3000", "http://localhost:3000", "http://127.0.0.1:3000"} {
		if _, err := normalizeIssuer(raw, true); err != nil {
			t.Fatalf("development loopback issuer rejected: %s: %v", raw, err)
		}
	}

	if _, err := normalizeIssuer("http://[::1]:3000", false); err == nil {
		t.Fatal("production IPv6 loopback issuer accepted")
	}

	if err := validateProviderEndpoint("http://remote.example/token", true); err == nil {
		t.Fatal("remote HTTP provider endpoint accepted in development")
	}

	if err := validateProviderEndpoint("http://[::1]:9000/token", true); err != nil {
		t.Fatalf("loopback HTTP provider endpoint rejected: %v", err)
	}
}

func TestOAuthCallbackRejectsDuplicateParameters(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "http://localhost:3000"
	cfg.OAuth2.Providers = []Provider{{ID: "fake", Name: "Fake", Provider: "custom", Namespace: "fake", AuthorizationURL: "http://localhost/authorize", TokenURL: "http://localhost/token", UserInfoURL: "http://localhost/userinfo", ClientID: "client", ClientSecret: strings.Repeat("p", 32), RedirectURL: "http://localhost:3000/oauth2/fake/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	store.applicationHandler(cfg).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth2/fake/callback?state=one&state=two", nil))
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "one") {
		t.Fatalf("duplicate callback parameters were not rejected safely: %d %s", response.Code, response.Body.String())
	}
}

func TestOAuthCallbackHandlesProviderError(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "http://localhost:3000"
	cfg.OAuth2.Providers = []Provider{{ID: "fake", Name: "Fake", Provider: "custom", Namespace: "fake", AuthorizationURL: "http://localhost/authorize", TokenURL: "http://localhost/token", UserInfoURL: "http://localhost/userinfo", ClientID: "client", ClientSecret: strings.Repeat("p", 32), RedirectURL: "http://localhost:3000/oauth2/fake/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.upstreamStates["known"] = &UpstreamState{Value: "known", ProviderID: "fake", EnrollmentID: "missing", ExpiresAt: time.Now().Add(time.Minute)}

	response := httptest.NewRecorder()
	store.applicationHandler(cfg).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth2/fake/callback?state=known&error=access_denied&error_description=secret", nil))
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "secret") || !strings.Contains(response.Body.String(), "not approved") {
		t.Fatalf("provider error was not handled safely: %d %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentResponseExpiryMatchesCredential(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pqKey := testMLDSAKey(t)
	enrollment := &Enrollment{ID: "enrollment", State: "verified", Payload: "payload", Expires: time.Now().Add(time.Minute), PublicKey: &key.PublicKey, MLDSA65PublicKey: pqKey.PublicKey(), Device: &Device{Sub: "device", Email: "person@example.com", Provider: "google", UpstreamNamespace: "relay:oauth2:google", UpstreamSub: "subject", JTI: "jti", PublicKey: &key.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}}
	store.enrollmentState[enrollment.ID] = enrollment
	signature, err := ecdsa.SignASN1(rand.Reader, key, sum([]byte(enrollment.Payload)))
	if err != nil {
		t.Fatal(err)
	}

	mldsaSignature, err := pqKey.Sign(nil, []byte(enrollment.Payload), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	credential, expiresAt, err := store.completeEnrollment(enrollment.ID, map[string]string{"p256": b64.EncodeToString(signature), "mldsa65": b64.EncodeToString(mldsaSignature)}, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	verified, err := store.verifyCredential(credential, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !verified.Exp.Equal(expiresAt.Truncate(time.Second)) {
		t.Fatalf("credential expiry %v did not match response expiry %v", verified.Exp, expiresAt)
	}
}

func TestEnrollmentStateCapacityLimit(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for index := range maxActiveEnrollments {
		store.enrollmentState[fmt.Sprintf("enrollment-%d", index)] = &Enrollment{ID: fmt.Sprintf("enrollment-%d", index), Expires: time.Now().Add(time.Hour), State: "pending"}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pqKey := testMLDSAKey(t)
	body, _ := json.Marshal(map[string]any{"device_name": "Capacity test", "keys": map[string]any{"p256": pubJWK(&key.PublicKey), "mldsa65": b64.EncodeToString(pqKey.PublicKey().Bytes())}})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/enrollments", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	store.applicationHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("enrollment capacity returned %d", response.Code)
	}
}

func TestSSESurvivesServerWriteTimeout(t *testing.T) {
	cfg := defaults()
	cfg.Lifetimes.Login = 2 * time.Second
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.loginState["sse-login"] = &Login{ID: "sse-login", BrowserSecret: "browser-secret", Expires: time.Now().Add(cfg.Lifetimes.Login), State: "pending"}

	server := httptest.NewUnstartedServer(store.applicationHandler(cfg))
	server.Config.WriteTimeout = 20 * time.Millisecond
	server.Start()
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/logins/sse-login/events", nil)
	if err != nil {
		t.Fatal(err)
	}

	request.AddCookie(&http.Cookie{Name: browserCookiePrefix + "sse-login", Value: "browser-secret"})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	if _, err := store.transitionLogin("sse-login", "pending", "approved", nil); err != nil {
		t.Fatal(err)
	}

	foundApproved := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if strings.Contains(line, "approved") {
			foundApproved = true
			break
		}
	}

	if !foundApproved {
		t.Fatal("SSE stream did not survive the server write timeout")
	}
}

func TestConfigurationIsFileOnly(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	raw := "issuer: https://yaml.example\nlisten: 3000\ndevelopment: true\noidc:\n  clients: []\noauth2:\n  providers: []\n"
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(file)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Issuer != "https://yaml.example" || cfg.Listen != "3000" || len(cfg.OAuth2.Providers) != 0 {
		t.Fatalf("file configuration was not loaded: %#v", cfg)
	}
}

func TestEnrollmentReturnURIValidation(t *testing.T) {
	for _, value := range []string{"https://client.example.com/relay/complete", "relayid://enrollment/complete", "http://127.0.0.1:3000/complete"} {
		if err := validateEnrollmentReturnURI(value, true); err != nil {
			t.Fatalf("valid return URI %q was rejected: %v", value, err)
		}
	}

	for _, value := range []string{"javascript://run", "https://client.example.com/complete?existing=query", "http://client.example.com/complete"} {
		if err := validateEnrollmentReturnURI(value, false); err == nil {
			t.Fatalf("unsafe return URI %q was accepted", value)
		}
	}

	redirect, err := appendEnrollmentReturn("relayid://enrollment/complete", "enrollment-id")
	if err != nil || !strings.Contains(redirect, "enrollment_id=enrollment-id") || !strings.Contains(redirect, "state=verified") {
		t.Fatalf("return URI was not completed correctly: %q %v", redirect, err)
	}
}

func TestExactRedirectMatching(t *testing.T) {
	cfg := defaults()
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", RedirectURIs: []string{"https://client.example.com/callback"}}}
	if findOIDCClient(cfg, "client") == nil || contains(cfg.OIDC.Clients[0].RedirectURIs, "https://client.example.com/callback.evil") {
		t.Fatal("redirect matching is not exact")
	}
}

func TestPKCES256IsRawBase64URL(t *testing.T) {
	if pkceS256("verifier") != "iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ" {
		t.Fatalf("unexpected PKCE challenge: %s", pkceS256("verifier"))
	}
}

func TestPKCEVerifierSyntax(t *testing.T) {
	if !isPKCEVerifier(strings.Repeat("a", 43)) {
		t.Fatal("valid PKCE verifier was rejected")
	}

	for _, value := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "!"} {
		if isPKCEVerifier(value) {
			t.Fatalf("invalid PKCE verifier was accepted: %q", value)
		}
	}
}

func TestRelayQRValueIsAnAppConfigurationLink(t *testing.T) {
	want := "relayid://relay?origin=https%3A%2F%2Frelay.example.com"
	if got := relayQRValue("https://relay.example.com"); got != want {
		t.Fatalf("Relay QR value = %q, want %q", got, want)
	}
}

func TestLoginQRValueIsAnAppApprovalLink(t *testing.T) {
	want := "relayid://login?origin=https%3A%2F%2Frelay.example.com&id=login-1"
	if got := loginQRValue("https://relay.example.com", "login-1"); got != want {
		t.Fatalf("login QR value = %q, want %q", got, want)
	}
}

func TestBrowserPagesAndQRRoute(t *testing.T) {
	cfg := defaults()
	cfg.OIDC.Clients = []OIDCClient{{
		ID:           "cloudflare",
		RedirectURIs: []string{"https://client.example.com/callback"},
	}}

	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	s.loginState["login-id"] = &Login{
		ID:            "login-id",
		ClientID:      "cloudflare",
		BrowserSecret: "browser-secret",
		Challenge:     "challenge",
		Expires:       time.Now().Add(time.Minute),
		State:         "pending",
	}

	handler := withBrowserRoutes(
		s.routes(cfg),
		s.loginPage(cfg),
		s.loginSubmit(cfg),
		s.enrollPage(cfg),
		s.errorPage("not found"),
	)

	markers := map[string]string{"/": "RelayId", "/enroll": "Start enrollment from the RelayId app", "/error": "The request could not be completed", "/login/login-id": "Sign in", "/how-it-works": "How RelayId works"}
	for _, path := range []string{"/", "/enroll", "/error", "/login/login-id", "/how-it-works"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if path == "/login/login-id" {
			request.AddCookie(&http.Cookie{Name: browserCookiePrefix + "login-id", Value: "browser-secret"})
		}

		handler.ServeHTTP(recorder, request)
		expectedStatus := http.StatusOK
		if path == "/error" {
			expectedStatus = http.StatusNotFound
		}

		if recorder.Code != expectedStatus || !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: status=%d content-type=%q", path, recorder.Code, recorder.Header().Get("Content-Type"))
		}

		if !strings.Contains(recorder.Body.String(), markers[path]) {
			t.Fatalf("%s rendered the wrong template", path)
		}
	}

	loginPageWithoutCode := httptest.NewRecorder()
	requestWithoutCode := httptest.NewRequest(http.MethodGet, "/login/login-id", nil)
	requestWithoutCode.AddCookie(&http.Cookie{Name: browserCookiePrefix + "login-id", Value: "browser-secret"})
	handler.ServeHTTP(loginPageWithoutCode, requestWithoutCode)
	if strings.Contains(loginPageWithoutCode.Body.String(), "one-time-code") {
		t.Fatal("disabled mobile code was rendered")
	}

	cfg.MobileCode.Enabled = true
	loginPageWithCode := httptest.NewRecorder()
	requestWithCode := httptest.NewRequest(http.MethodGet, "/login/login-id", nil)
	requestWithCode.AddCookie(&http.Cookie{Name: browserCookiePrefix + "login-id", Value: "browser-secret"})
	withBrowserRoutes(s.routes(cfg), s.loginPage(cfg), s.loginSubmit(cfg), s.enrollPage(cfg), s.errorPage("not found")).ServeHTTP(loginPageWithCode, requestWithCode)
	if !strings.Contains(loginPageWithCode.Body.String(), "one-time-code") {
		t.Fatal("enabled mobile code was not rendered")
	}

	for _, path := range []string{"/assets/css/app.css", "/assets/js/login.js", "/assets/js/enrollment.js"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("asset %s: status=%d length=%d", path, recorder.Code, recorder.Body.Len())
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/qr/login-id", nil))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(recorder.Body.Bytes(), []byte{0x89, 'P', 'N', 'G'}) {
		t.Fatalf("QR route did not return a PNG: status=%d type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}

	methodRecorder := httptest.NewRecorder()
	handler.ServeHTTP(methodRecorder, httptest.NewRequest(http.MethodPost, "/api/qr/login-id", nil))
	if methodRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("QR route accepted non-GET method: %d", methodRecorder.Code)
	}

	s.loginState["expired-login"] = &Login{ID: "expired-login", Expires: time.Now().Add(-time.Minute), State: "pending"}
	expiredRecorder := httptest.NewRecorder()
	handler.ServeHTTP(expiredRecorder, httptest.NewRequest(http.MethodGet, "/api/qr/expired-login", nil))
	if expiredRecorder.Code != http.StatusGone {
		t.Fatalf("expired QR route returned %d", expiredRecorder.Code)
	}

	s.loginState["expired-approved"] = &Login{ID: "expired-approved", Expires: time.Now().Add(-time.Minute), State: "approved"}
	expiredApprovedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(expiredApprovedRecorder, httptest.NewRequest(http.MethodGet, "/api/qr/expired-approved", nil))
	if expiredApprovedRecorder.Code != http.StatusGone || s.loginState["expired-approved"].State != "expired" {
		t.Fatalf("approved expired QR route returned status=%d state=%s", expiredApprovedRecorder.Code, s.loginState["expired-approved"].State)
	}
}

func TestEnrollmentPageShowsDeviceWarningOnlyWhilePending(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	store.enrollmentState["enrollment"] = &Enrollment{ID: "enrollment", Name: "Office laptop", State: "pending", Expires: time.Now().Add(time.Minute)}
	page := store.enrollPage(defaults())
	response := httptest.NewRecorder()
	page.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/enroll/enrollment", nil))
	if !strings.Contains(response.Body.String(), "Office laptop") || !strings.Contains(response.Body.String(), "Continue only if you just started enrollment") {
		t.Fatal("pending enrollment did not show device identity and warning")
	}

	store.enrollmentState["enrollment"].State = "complete"
	response = httptest.NewRecorder()
	page.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/enroll/enrollment", nil))
	if strings.Contains(response.Body.String(), "No provider configured") || strings.Contains(response.Body.String(), "Continue only if you just started enrollment") {
		t.Fatal("terminal enrollment showed pending-only content")
	}
}

func TestPreviewPagesAreConfigurable(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := store.applicationHandler(cfg)
	for _, path := range []string{"/", "/how-it-works", "/test/enroll", "/test/enroll/preview-enrollment", "/test/login", "/test/error"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK && path != "/test/error" {
			t.Fatalf("preview page %s returned %d", path, response.Code)
		}
		if !strings.Contains(response.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("preview page %s returned %q", path, response.Header().Get("Content-Type"))
		}
	}

	qr := httptest.NewRecorder()
	handler.ServeHTTP(qr, httptest.NewRequest(http.MethodGet, "/test/qr", nil))
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("preview QR returned status=%d type=%q", qr.Code, qr.Header().Get("Content-Type"))
	}

	for _, test := range []struct {
		name     string
		query    string
		showCode bool
	}{
		{name: "config disabled by default", query: "", showCode: false},
		{name: "query enables code", query: "?mobile_code=on", showCode: true},
		{name: "query disables code", query: "?mobile_code=off", showCode: false},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test/login"+test.query, nil))
		containsCode := strings.Contains(response.Body.String(), "one-time-code")
		if containsCode != test.showCode {
			t.Fatalf("%s: code visible=%t, want %t", test.name, containsCode, test.showCode)
		}
	}

	groups := httptest.NewRecorder()
	handler.ServeHTTP(groups, httptest.NewRequest(http.MethodGet, "/test/login?mobile_code=on&groups=2", nil))
	if !strings.Contains(groups.Body.String(), `data-code-groups="2"`) {
		t.Fatal("preview login groups query was not applied")
	}

	cfg.ServeTestPages = false
	handler = store.applicationHandler(cfg)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test/login", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled preview page returned %d", response.Code)
	}
}

func TestLoginPageRendersWithoutProviderContextClutter(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	store.renderPage(response, "login", pageData{
		Title:        "Sign in",
		QRURL:        "/test/qr",
		ID:           "preview-login",
		RelyingParty: "<Example relying party>",
		Scopes:       []string{"Sign in", "Email address"},
	})
	body := response.Body.String()
	for _, expected := range []string{"Sign in", "Scan with the Relay app"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("login page missing %q", expected)
		}
	}
	for _, removed := range []string{"Sign in to:", "Requested access", "Continue only if you initiated this sign-in."} {
		if strings.Contains(body, removed) {
			t.Fatalf("login page still contains removed context %q", removed)
		}
	}
}

func TestSystemStatsAreOptional(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	without := httptest.NewRecorder()
	store.routes(cfg).ServeHTTP(without, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var disabled struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(without.Body).Decode(&disabled); err != nil {
		t.Fatal(err)
	}
	if _, ok := disabled.Data["system"]; ok {
		t.Fatal("system stats were exposed while disabled")
	}

	cfg.ExposeSystemStats = true
	with := httptest.NewRecorder()
	store.routes(cfg).ServeHTTP(with, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var enabled struct {
		Data struct {
			System map[string]any `json:"system"`
		} `json:"data"`
	}
	if err := json.NewDecoder(with.Body).Decode(&enabled); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"cpu_percent", "memory_used_bytes"} {
		if _, ok := enabled.Data.System[field]; !ok {
			t.Fatalf("system stats missing %s: %#v", field, enabled.Data.System)
		}
	}
}

func TestBrowserRoutesReceiveSecurityHeaders(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/callback"}}}

	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := store.applicationHandler(cfg)
	paths := []string{"/", "/enroll", "/error", "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid"}
	for _, path := range paths {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-Robots-Tag", "Cache-Control", "Strict-Transport-Security", "X-Request-ID"} {
			if response.Header().Get(header) == "" {
				t.Fatalf("%s missing %s", path, header)
			}
		}

		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s missing no-store cache policy", path)
		}
	}
}

func TestHTMLSignalErrorHasCorrectWireContentType(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(store.applicationHandler(defaults()))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/error")
	if err != nil {
		t.Fatal(err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound || response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("unexpected wire error response: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

func TestReadJSONRejectsOversizedBody(t *testing.T) {
	body := bytes.Repeat([]byte("x"), (1<<20)+1)
	request := httptest.NewRequest(http.MethodPost, "/api/enrollments", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := readJSON(request, &map[string]any{}); err == nil {
		t.Fatal("oversized JSON body was accepted")
	}
}

func TestConcurrentHTTPLoginReadsAndTransitions(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	store.loginState["concurrent"] = &Login{ID: "concurrent", State: "pending", Challenge: "challenge", BrowserSecret: "secret", Expires: time.Now().Add(time.Minute)}
	server := httptest.NewServer(store.applicationHandler(defaults()))
	defer server.Close()

	var wait sync.WaitGroup
	for range 20 {
		wait.Go(func() {
			response, err := server.Client().Get(server.URL + "/api/logins/concurrent")
			if err == nil {
				_ = response.Body.Close()
			}
		})
	}

	wait.Go(func() {
		_, _ = store.transitionLogin("concurrent", "pending", "approved", &Device{UpstreamNamespace: "https://issuer", Provider: "provider", UpstreamSub: "subject"})
	})
	wait.Wait()
}

func TestConcurrentHTTPEnrollmentReadsAndTransitions(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	store.enrollmentState["concurrent"] = &Enrollment{ID: "concurrent", State: "pending", Expires: time.Now().Add(time.Minute)}
	server := httptest.NewServer(store.applicationHandler(defaults()))
	defer server.Close()

	var wait sync.WaitGroup
	for range 20 {
		wait.Go(func() {
			response, err := server.Client().Get(server.URL + "/api/enrollments/concurrent")
			if err == nil {
				_ = response.Body.Close()
			}
		})
	}

	wait.Go(func() {
		_ = store.verifyEnrollment("concurrent", &Device{UpstreamNamespace: "https://issuer", Email: "person@example.com"}, "person@example.com", "payload", time.Now())
	})

	wait.Wait()
}

func TestDeniedLoginCannotBeApprovedByCode(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	device := &Device{Provider: "test", UpstreamSub: "subject"}
	now := time.Now()
	store.loginState["login"] = &Login{ID: "login", State: "denied", Expires: now.Add(time.Minute)}
	store.mobileCodes["ABCD1234"] = &MobileCode{Device: device, ExpiresAt: now.Add(time.Minute)}

	if err := store.approveLoginWithMobileCode("login", "ABCD1234", now); err == nil {
		t.Fatal("denied login was approved")
	}

	if _, ok := store.mobileCodes["ABCD1234"]; !ok {
		t.Fatal("mobile code was consumed for denied login")
	}
}

func TestApprovedLoginCannotCompleteAfterExpiry(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	store.loginState["login"] = &Login{ID: "login", State: "approved", Expires: time.Now().Add(-time.Minute), Device: &Device{UpstreamNamespace: "https://issuer", UpstreamSub: "subject", Provider: "provider", Email: "person@example.com"}}
	if _, err := store.finishApproved("login"); err == nil {
		t.Fatal("expired login completed")
	}

	if store.loginState["login"].State != "expired" || len(store.authCodes) != 0 {
		t.Fatal("expired login state or authorization code was incorrect")
	}
}

func TestExpiredLoginDoesNotOverwriteTerminalState(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	for _, state := range []string{"denied", "completed", "expired"} {
		store.loginState[state] = &Login{ID: state, State: state, Expires: time.Now().Add(-time.Minute)}
		if _, err := store.transitionLogin(state, state, "expired", nil); err == nil {
			t.Fatalf("terminal %s state transitioned", state)
		}
		if store.loginState[state].State != state {
			t.Fatalf("terminal %s state was overwritten", state)
		}
	}
}

func TestConcurrentApproveAndDenyOnlyOneSucceeds(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	store.loginState["login"] = &Login{ID: "login", State: "pending", Expires: time.Now().Add(time.Minute)}
	device := &Device{UpstreamNamespace: "https://issuer", UpstreamSub: "subject", Provider: "provider"}
	results := make(chan error, 2)

	go func() { _, err := store.transitionLogin("login", "pending", "approved", device); results <- err }()
	go func() { _, err := store.transitionLogin("login", "pending", "denied", nil); results <- err }()

	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatal("concurrent login transitions did not have exactly one winner")
	}
}

func TestEnrollmentVerificationIsSingleUse(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	store.enrollmentState["enrollment"] = &Enrollment{ID: "enrollment", State: "pending", Expires: now.Add(time.Minute)}
	results := make(chan error, 2)

	for _, email := range []string{"one@example.com", "two@example.com"} {
		go func(email string) {
			results <- store.verifyEnrollment("enrollment", &Device{Email: email}, email, "payload-"+email, now)
		}(email)
	}

	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatal("enrollment verification was not single-use")
	}

	if store.enrollmentState["enrollment"].State != "verified" {
		t.Fatal("enrollment did not remain verified")
	}
}

func TestGoogleVerifiedEmailAccepted(t *testing.T) {
	email, err := evaluateOAuthEmail(&oauth.UserInfo{ProviderID: "subject", Email: "Person@Example.com", EmailVerified: true})
	if err != nil || email != "person@example.com" {
		t.Fatalf("verified Google email was not accepted: %q %v", email, err)
	}
}

func TestUnverifiedOAuthEmailIsRejectedForEveryProvider(t *testing.T) {
	for _, provider := range []string{"google", "github", "discord", "gitlab", "linkedin", "oidc", "custom"} {
		t.Run(provider, func(t *testing.T) {
			if _, err := evaluateOAuthEmail(&oauth.UserInfo{ProviderID: "subject", Email: "person@example.com"}); err == nil {
				t.Fatal("unverified email was accepted")
			}
		})
	}
}

func TestOAuthIdentityFieldsAreBounded(t *testing.T) {
	tests := []struct {
		name string
		info oauth.UserInfo
	}{
		{name: "subject", info: oauth.UserInfo{ProviderID: strings.Repeat("s", 513), Email: "person@example.com", EmailVerified: true}},
		{name: "email", info: oauth.UserInfo{ProviderID: "subject", Email: strings.Repeat("e", 321), EmailVerified: true}},
		{name: "name", info: oauth.UserInfo{ProviderID: "subject", Email: "person@example.com", EmailVerified: true, Name: strings.Repeat("n", 257)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := evaluateOAuthEmail(&test.info); err == nil {
				t.Fatal("oversized identity field was accepted")
			}
		})
	}
}

func TestOversizedOIDCStateIsRejectedWithoutReflection(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.example.com/callback"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	state := strings.Repeat("x", 2048)
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&response_type=code&scope=openid&state="+url.QueryEscape(state), nil)
	response := httptest.NewRecorder()
	store.applicationHandler(cfg).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized state returned %d", response.Code)
	}
	if strings.Contains(response.Header().Get("Location"), state) || strings.Contains(response.Body.String(), state) {
		t.Fatal("oversized state was reflected")
	}
}

func TestCustomAuthorizationUsesConfiguredScopesAndPKCE(t *testing.T) {
	provider, err := newOAuthProvider(context.Background(), Provider{ID: "generic", Provider: "custom", AuthorizationURL: "https://accounts.example.com/authorize", TokenURL: "https://accounts.example.com/token", UserInfoURL: "https://accounts.example.com/userinfo", ClientID: "client", ClientSecret: "secret", Scopes: []string{"email", "profile"}}, false)
	if err != nil {
		t.Fatal(err)
	}

	authURL := provider.AuthCodeURL("state", "https://relay.example.com/oauth2/generic/callback", "verifier")
	values, err := url.Parse(authURL)
	if err != nil || values.Query().Get("scope") != "email profile" || values.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected custom authorization URL: %s", authURL)
	}
}

func TestProviderPresetFactories(t *testing.T) {
	tests := []struct {
		name     string
		provider string
	}{
		{name: "google", provider: "google"},
		{name: "github", provider: "github"},
		{name: "discord", provider: "discord"},
		{name: "gitlab", provider: "gitlab"},
		{name: "linkedin", provider: "linkedin"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := newOAuthProvider(context.Background(), Provider{ID: test.name, Provider: test.provider, ClientID: "client", ClientSecret: "secret"}, false)
			if err != nil {
				t.Fatal(err)
			}

			if provider.AuthCodeURL("state", "https://relay.example.com/oauth2/"+test.name+"/callback", "verifier") == "" {
				t.Fatal("provider returned an empty authorization URL")
			}
		})
	}

	custom, err := newOAuthProvider(context.Background(), Provider{ID: "custom", Provider: "custom", AuthorizationURL: "https://accounts.example.com/authorize", TokenURL: "https://accounts.example.com/token", UserInfoURL: "https://accounts.example.com/userinfo", Scopes: []string{"email"}, ClientID: "client", ClientSecret: "secret"}, false)
	if err != nil || custom.AuthCodeURL("state", "https://relay.example.com/oauth2/custom/callback", "verifier") == "" {
		t.Fatalf("custom provider was not constructed: %v", err)
	}
}

func TestStablePresetNamespaceSurvivesProviderIDRename(t *testing.T) {
	first := providerNamespace(Provider{ID: "google-primary", Provider: "google"})
	second := providerNamespace(Provider{ID: "personal-google", Provider: "google"})
	if first != "relay:oauth2:google" || first != second {
		t.Fatalf("preset namespace changed with local ID: %q %q", first, second)
	}

	if got := providerNamespace(Provider{ID: "custom", Provider: "custom", Namespace: "acme-production"}); got != "acme-production" {
		t.Fatalf("custom namespace was not preserved: %q", got)
	}
}

func TestGenericOIDCEnrollmentWithFakeProvider(t *testing.T) {
	providerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var fake *httptest.Server
	expectedNonce := ""
	fake = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": fake.URL, "authorization_endpoint": fake.URL + "/authorize",
				"token_endpoint": fake.URL + "/token", "jwks_uri": fake.URL + "/jwks", "userinfo_endpoint": fake.URL + "/userinfo",
				"id_token_signing_alg_values_supported": []string{"ES256"},
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "EC", "crv": "P-256", "x": pubJWK(&providerKey.PublicKey)["x"], "y": pubJWK(&providerKey.PublicKey)["y"], "kid": "fake-1", "alg": "ES256",
			}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Type", "application/json")
			_ = r.ParseForm()
			claims := jwt.MapClaims{"iss": fake.URL, "sub": "fake-sub", "aud": "fake-client", "email": "person@example.com", "email_verified": true, "name": "Person Example", "nonce": expectedNonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			tokenObject := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tokenObject.Header["kid"] = "fake-1"
			token, signErr := tokenObject.SignedString(providerKey)
			if signErr != nil {
				t.Errorf("sign fake token: %v", signErr)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fake-access", "id_token": token, "token_type": "Bearer"})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "fake-sub", "email": "person@example.com", "email_verified": true, "name": "Person Example"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)

	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OAuth2.Providers = []Provider{{ID: "fake", Name: "Fake", Provider: "oidc", Issuer: fake.URL, ClientID: "fake-client", ClientSecret: "fake-secret", RedirectURL: "https://relay.example.com/oauth2/fake/callback"}}
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := withBrowserRoutes(s.routes(cfg), s.loginPage(cfg), s.loginSubmit(cfg), s.enrollPage(cfg), s.errorPage("not found"))
	server := httptest.NewServer(handler)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	createBody, _ := json.Marshal(map[string]any{"device_name": "Test device", "keys": map[string]any{"p256": pubJWK(&deviceKey.PublicKey), "mldsa65": b64.EncodeToString(pqKey.PublicKey().Bytes())}})
	createResponse, err := client.Post(server.URL+"/api/enrollments", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}

	defer createResponse.Body.Close()
	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if json.NewDecoder(createResponse.Body).Decode(&created) != nil || created.Data.ID == "" {
		t.Fatal("enrollment was not created through HTTP")
	}

	enrollmentID := created.Data.ID
	start, err := client.Get(server.URL + "/oauth2/fake?enrollment_id=" + url.QueryEscape(enrollmentID))
	if err != nil {
		t.Fatal(err)
	}

	if start.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("upstream start status=%d", start.StatusCode)
	}

	location, err := url.Parse(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("state missing from upstream authorization")
	}
	expectedNonce = location.Query().Get("nonce")

	callback, err := client.Get(server.URL + "/oauth2/fake/callback?state=" + url.QueryEscape(state) + "&code=fake-code")
	if err != nil {
		t.Fatal(err)
	}

	if callback.StatusCode != http.StatusFound {
		t.Fatalf("upstream callback status=%d", callback.StatusCode)
	}

	if strings.Contains(state, enrollmentID) {
		t.Fatal("upstream OAuth state leaked enrollment ID")
	}

	replay, err := client.Get(server.URL + "/oauth2/fake/callback?state=" + url.QueryEscape(state) + "&code=fake-code")
	if err != nil {
		t.Fatal(err)
	}

	if replay.StatusCode == http.StatusFound {
		t.Fatal("upstream OAuth state was reusable")
	}

	statusResponse, err := client.Get(server.URL + "/api/enrollments/" + enrollmentID)
	if err != nil {
		t.Fatal(err)
	}

	var verified struct {
		Data struct {
			State          string `json:"state"`
			SigningPayload string `json:"signing_payload"`
		} `json:"data"`
	}

	if json.NewDecoder(statusResponse.Body).Decode(&verified) != nil || verified.Data.State != "verified" || verified.Data.SigningPayload == "" {
		t.Fatal("verified enrollment was not returned through HTTP")
	}

	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(verified.Data.SigningPayload)))
	if err != nil {
		t.Fatal(err)
	}
	mldsaSignature, err := pqKey.Sign(nil, []byte(verified.Data.SigningPayload), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"signatures": map[string]string{"p256": b64.EncodeToString(signature), "mldsa65": b64.EncodeToString(mldsaSignature)}})
	complete, err := client.Post(server.URL+"/api/enrollments/"+enrollmentID+"/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	if complete.StatusCode != http.StatusOK {
		t.Fatalf("enrollment completion status=%d", complete.StatusCode)
	}

	var response struct {
		Data map[string]string `json:"data"`
	}

	if err := json.NewDecoder(complete.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	if _, err := s.verifyCredential(response.Data["credential"], cfg); err != nil {
		t.Fatalf("issued credential did not verify: %v", err)
	}
}

func TestEndToEndEnrollThenQRLogin(t *testing.T) {
	providerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expectedNonce := ""
	var fake *httptest.Server
	fake = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": fake.URL, "authorization_endpoint": fake.URL + "/authorize", "token_endpoint": fake.URL + "/token", "jwks_uri": fake.URL + "/jwks", "userinfo_endpoint": fake.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"ES256"},
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": pubJWK(&providerKey.PublicKey)["x"], "y": pubJWK(&providerKey.PublicKey)["y"], "kid": "provider-key", "alg": "ES256"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			claims := jwt.MapClaims{"iss": fake.URL, "sub": "e2e-subject", "aud": "e2e-client", "email": "e2e@example.com", "email_verified": true, "nonce": expectedNonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = "provider-key"
			raw, _ := token.SignedString(providerKey)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "e2e-access", "id_token": raw, "token_type": "Bearer"})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "e2e-subject", "email": "e2e@example.com", "email_verified": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()

	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "e2e-client", Secret: strings.Repeat("c", 32), RedirectURIs: []string{"https://client.example/callback"}}}
	cfg.OAuth2.Providers = []Provider{{ID: "fake", Name: "Fake", Provider: "oidc", Issuer: fake.URL, ClientID: "e2e-client", ClientSecret: strings.Repeat("p", 32), RedirectURL: "https://relay.example.com/oauth2/fake/callback"}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(store.applicationHandler(cfg))
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)

	createBody, _ := json.Marshal(map[string]any{"device_name": "E2E phone", "keys": map[string]any{"p256": pubJWK(&deviceKey.PublicKey), "mldsa65": b64.EncodeToString(pqKey.PublicKey().Bytes())}})
	createResponse, err := client.Post(server.URL+"/api/enrollments", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}

	var created struct {
		Data struct {
			ID               string `json:"id"`
			AuthorizationURL string `json:"authorization_url"`
		} `json:"data"`
	}

	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	_ = createResponse.Body.Close()

	authorizationURL, _ := url.Parse(created.Data.AuthorizationURL)
	_, err = client.Get(server.URL + authorizationURL.Path + "?" + authorizationURL.RawQuery)
	if err != nil {
		t.Fatal(err)
	}

	start, err := client.Get(server.URL + "/oauth2/fake?enrollment_id=" + url.QueryEscape(created.Data.ID))
	if err != nil {
		t.Fatal(err)
	}

	upstreamURL, _ := url.Parse(start.Header.Get("Location"))
	expectedNonce = upstreamURL.Query().Get("nonce")
	state := upstreamURL.Query().Get("state")
	_ = start.Body.Close()

	callback, err := client.Get(server.URL + "/oauth2/fake/callback?state=" + url.QueryEscape(state) + "&code=e2e-code")
	if err != nil || callback.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callback.Body)
		t.Fatalf("upstream callback failed: %v status=%d body=%s", err, callback.StatusCode, body)
	}

	_ = callback.Body.Close()

	enrollmentResponse, err := client.Get(server.URL + "/api/enrollments/" + created.Data.ID)
	if err != nil {
		t.Fatal(err)
	}

	var enrollment struct {
		Data struct {
			State          string `json:"state"`
			SigningPayload string `json:"signing_payload"`
		} `json:"data"`
	}

	_ = json.NewDecoder(enrollmentResponse.Body).Decode(&enrollment)
	_ = enrollmentResponse.Body.Close()
	if enrollment.Data.State != "verified" || enrollment.Data.SigningPayload == "" {
		t.Fatal("public enrollment did not produce signing payload")
	}

	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(enrollment.Data.SigningPayload)))
	if err != nil {
		t.Fatal(err)
	}
	mldsaSignature, err := pqKey.Sign(nil, []byte(enrollment.Data.SigningPayload), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	completeBody, _ := json.Marshal(map[string]any{"signatures": map[string]string{"p256": b64.EncodeToString(signature), "mldsa65": b64.EncodeToString(mldsaSignature)}})
	completeResponse, err := client.Post(server.URL+"/api/enrollments/"+created.Data.ID+"/complete", "application/json", bytes.NewReader(completeBody))
	if err != nil {
		t.Fatal(err)
	}

	var completed struct {
		Data struct {
			Credential string `json:"credential"`
		} `json:"data"`
	}

	_ = json.NewDecoder(completeResponse.Body).Decode(&completed)
	_ = completeResponse.Body.Close()
	if completed.Data.Credential == "" {
		t.Fatal("public enrollment did not return credential")
	}

	verifier := strings.Repeat("v", 43)
	query := url.Values{"client_id": {"e2e-client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid email profile"}, "state": {"e2e-state"}, "nonce": {"e2e-nonce"}, "code_challenge": {pkceS256(verifier)}, "code_challenge_method": {"S256"}}
	authorizeResponse, err := client.Get(server.URL + "/oidc/authorize?" + query.Encode())
	if err != nil || authorizeResponse.StatusCode != http.StatusFound {
		t.Fatalf("authorize failed: %v status=%d", err, authorizeResponse.StatusCode)
	}

	loginURL, _ := url.Parse(authorizeResponse.Header.Get("Location"))
	loginID := strings.TrimPrefix(loginURL.Path, "/login/")
	_ = authorizeResponse.Body.Close()

	loginInfo, err := client.Get(server.URL + "/api/logins/" + loginID)
	if err != nil {
		t.Fatal(err)
	}

	var login struct {
		Data struct {
			Challenge string `json:"challenge"`
		} `json:"data"`
	}

	_ = json.NewDecoder(loginInfo.Body).Decode(&login)
	_ = loginInfo.Body.Close()

	approveBody, _ := json.Marshal(map[string]string{"challenge": login.Data.Challenge})
	approveRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/logins/"+loginID+"/approve", bytes.NewReader(approveBody))
	approveRequest.Header.Set("Content-Type", "application/json")
	approveRequest.Header.Set("Authorization", "RelayDevice "+completed.Data.Credential)
	signTestRequest(t, approveRequest, deviceKey, pqKey)
	approveResponse, err := client.Do(approveRequest)
	if err != nil || approveResponse.StatusCode != http.StatusOK {
		t.Fatalf("device approval failed: %v status=%d", err, approveResponse.StatusCode)
	}

	_ = approveResponse.Body.Close()

	replayRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/logins/"+loginID+"/approve", bytes.NewReader(approveBody))
	for name, values := range approveRequest.Header {
		for _, value := range values {
			replayRequest.Header.Add(name, value)
		}
	}

	replayResponse, err := client.Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}

	if replayResponse.StatusCode == http.StatusOK {
		t.Fatal("exact signed device approval request was replayed")
	}

	_ = replayResponse.Body.Close()

	loginResponse, err := client.Get(server.URL + "/login/" + loginID)
	if err != nil || loginResponse.StatusCode != http.StatusFound {
		t.Fatalf("browser completion failed: %v status=%d", err, loginResponse.StatusCode)
	}

	callbackURL, _ := url.Parse(loginResponse.Header.Get("Location"))
	_ = loginResponse.Body.Close()

	tokenForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {"e2e-client"}, "client_secret": {strings.Repeat("c", 32)}, "redirect_uri": {"https://client.example/callback"}, "code": {callbackURL.Query().Get("code")}, "code_verifier": {verifier}}
	tokenResponse, err := client.PostForm(server.URL+"/oidc/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}

	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	_ = json.NewDecoder(tokenResponse.Body).Decode(&tokens)
	_ = tokenResponse.Body.Close()
	if tokens.IDToken == "" || tokens.AccessToken == "" {
		t.Fatal("token exchange did not return both tokens")
	}

	verifyRelayIDTokenWithJWKS(t, server.URL, tokens.IDToken, "e2e-client", "e2e-nonce", cfg.Issuer, hash("relay/subject\n"+fake.URL+"\ne2e-subject"), "e2e@example.com")

	userRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/oidc/userinfo", nil)
	userRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	userResponse, err := client.Do(userRequest)
	if err != nil || userResponse.StatusCode != http.StatusOK {
		t.Fatalf("userinfo failed: %v status=%d", err, userResponse.StatusCode)
	}

	var userInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}

	if err := json.NewDecoder(userResponse.Body).Decode(&userInfo); err != nil {
		t.Fatal(err)
	}

	_ = userResponse.Body.Close()
	if userInfo.Sub != hash("relay/subject\n"+fake.URL+"\ne2e-subject") || userInfo.Email != "e2e@example.com" || !userInfo.EmailVerified {
		t.Fatalf("unexpected UserInfo: %#v", userInfo)
	}

	replayTokenResponse, _ := client.PostForm(server.URL+"/oidc/token", tokenForm)
	if replayTokenResponse.StatusCode == http.StatusOK {
		t.Fatal("authorization code was reusable")
	}
	_ = replayTokenResponse.Body.Close()

}

func verifyRelayIDTokenWithJWKS(t *testing.T, baseURL, raw, audience, nonce, issuer, subject, email string) {
	t.Helper()

	response, err := http.Get(baseURL + "/oidc/jwks")
	if err != nil {
		t.Fatal(err)
	}

	defer response.Body.Close()

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatal("invalid Relay JWKS")
	}

	publicKey, err := parseJWK(jwks.Keys[0])
	if err != nil {
		t.Fatal(err)
	}

	var claims jwt.MapClaims
	token, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != "ES256" || token.Header["kid"] != jwks.Keys[0]["kid"] {
			return nil, errors.New("unexpected token header")
		}

		return publicKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience))

	if err != nil || !token.Valid {
		t.Fatalf("ID token signature verification failed: %v", err)
	}

	if claims["token_use"] != "id" || claims["sub"] != subject || claims["email"] != email || claims["email_verified"] != true || claims["nonce"] != nonce {
		t.Fatalf("ID token claims were incorrect: %#v", claims)
	}
}

func TestCloudflareStyleOIDCRelyingPartyFlow(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "cloudflare", Secret: "cloudflare-secret", RedirectURIs: []string{"https://team.cloudflareaccess.com/callback"}}}
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pqKey := testMLDSAKey(t)
	device := &Device{UpstreamNamespace: "https://accounts.google.com", Sub: "device-sub", Email: "person@example.com", IdentityName: "Person Example", Provider: "cloudflare", UpstreamSub: "person", PublicKey: &deviceKey.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}
	handler := withBrowserRoutes(
		s.routes(cfg),
		s.loginPage(cfg),
		s.loginSubmit(cfg),
		s.enrollPage(cfg),
		s.errorPage("not found"),
	)

	verifier := "cloudflare-pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	authorize := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=cloudflare&redirect_uri=https%3A%2F%2Fteam.cloudflareaccess.com%2Fcallback&response_type=code&scope=openid%20email%20profile&state=state-123&nonce=nonce-123&code_challenge="+url.QueryEscape(pkceS256(verifier))+"&code_challenge_method=S256", nil)
	authorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizeResponse, authorize)
	if authorizeResponse.Code != http.StatusFound {
		t.Fatalf("authorization status=%d", authorizeResponse.Code)
	}

	loginURL, err := url.Parse(authorizeResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	loginID := strings.TrimPrefix(loginURL.Path, "/login/")
	loginInfo := httptest.NewRecorder()
	handler.ServeHTTP(loginInfo, httptest.NewRequest(http.MethodGet, "/api/logins/"+loginID, nil))
	var loginEnvelope struct {
		Data struct {
			Challenge string `json:"challenge"`
		} `json:"data"`
	}

	if err := json.Unmarshal(loginInfo.Body.Bytes(), &loginEnvelope); err != nil || loginEnvelope.Data.Challenge == "" {
		t.Fatalf("login info unavailable: %s", loginInfo.Body.String())
	}

	device.JTI = "test-jti"
	credential, err := s.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	approveBody, _ := json.Marshal(map[string]string{"challenge": loginEnvelope.Data.Challenge})
	approve := httptest.NewRequest(http.MethodPost, "/api/logins/"+loginID+"/approve", bytes.NewReader(approveBody))
	approve.Header.Set("Content-Type", "application/json")
	approve.Header.Set("Authorization", "RelayDevice "+credential)
	signTestRequest(t, approve, deviceKey, pqKey)
	approveResponse := httptest.NewRecorder()
	handler.ServeHTTP(approveResponse, approve)
	if approveResponse.Code != http.StatusOK {
		t.Fatalf("approval status=%d body=%s", approveResponse.Code, approveResponse.Body.String())
	}

	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodGet, loginURL.Path, nil)
	for _, cookie := range authorizeResponse.Result().Cookies() {
		loginRequest.AddCookie(cookie)
	}

	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login completion status=%d", loginResponse.Code)
	}

	callbackURL, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil || callbackURL.Query().Get("code") == "" || callbackURL.Query().Get("state") != "state-123" {
		t.Fatalf("invalid relying-party callback: %s", loginResponse.Header().Get("Location"))
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cloudflare"},
		"client_secret": {"cloudflare-secret"},
		"redirect_uri":  {"https://team.cloudflareaccess.com/callback"},
		"code":          {callbackURL.Query().Get("code")},
		"code_verifier": {verifier},
	}

	tokenRequest := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}

	var tokenBody struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenBody); err != nil || tokenBody.AccessToken == "" || tokenBody.IDToken == "" || tokenBody.AccessToken == tokenBody.IDToken {
		t.Fatalf("token response missing access token: %s", tokenResponse.Body.String())
	}

	var idClaims jwt.MapClaims
	if _, _, err := new(jwt.Parser).ParseUnverified(tokenBody.IDToken, &idClaims); err != nil || idClaims["token_use"] != "id" {
		t.Fatal("id token marker missing")
	}

	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, httptest.NewRequest(http.MethodGet, "/oidc/jwks", nil))
	if jwksResponse.Code != http.StatusOK || jwksResponse.Body.Len() == 0 {
		t.Fatalf("JWKS response was invalid: %d %s", jwksResponse.Code, jwksResponse.Body.String())
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}

	if json.Unmarshal(jwksResponse.Body.Bytes(), &jwks) != nil || len(jwks.Keys) == 0 {
		t.Fatal("JWKS key missing")
	}

	parsedID, _, _ := new(jwt.Parser).ParseUnverified(tokenBody.IDToken, jwt.MapClaims{})
	if parsedID.Header["kid"] != jwks.Keys[0]["kid"] {
		t.Fatal("JWT kid does not match JWKS")
	}

	for _, testCase := range []struct {
		method string
		scheme string
	}{
		{method: http.MethodGet, scheme: "bearer"},
		{method: http.MethodPost, scheme: "BeArEr"},
	} {
		userRequest := httptest.NewRequest(testCase.method, "/oidc/userinfo", nil)
		userRequest.Header.Set("Authorization", testCase.scheme+" "+tokenBody.AccessToken)
		userResponse := httptest.NewRecorder()
		handler.ServeHTTP(userResponse, userRequest)
		if userResponse.Code != http.StatusOK || !strings.Contains(userResponse.Body.String(), "person@example.com") || !strings.Contains(userResponse.Body.String(), "Person Example") {
			t.Fatalf("userinfo response was invalid: %d %s", userResponse.Code, userResponse.Body.String())
		}
	}

	idUserRequest := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	idUserRequest.Header.Set("Authorization", "Bearer "+tokenBody.IDToken)
	idUserResponse := httptest.NewRecorder()
	handler.ServeHTTP(idUserResponse, idUserRequest)
	if idUserResponse.Code != http.StatusUnauthorized {
		t.Fatal("userinfo accepted an ID token")
	}
}

func TestPublicHTTP(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := withBrowserRoutes(s.routes(cfg), s.loginPage(cfg), s.loginSubmit(cfg), s.enrollPage(cfg), s.errorPage("not found"))
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, path := range []string{"/", "/api/status", "/api/providers", "/.well-known/openid-configuration"} {
		response, requestErr := server.Client().Get(server.URL + path)
		if requestErr != nil {
			t.Fatal(requestErr)
		}

		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d", path, response.StatusCode)
		}

		_ = response.Body.Close()
	}

	response, requestErr := server.Client().Get(server.URL + "/api/status")
	if requestErr != nil {
		t.Fatal(requestErr)
	}

	defer response.Body.Close()
	var envelope struct {
		Status int            `json:"status"`
		Data   map[string]any `json:"data"`
	}

	if json.NewDecoder(response.Body).Decode(&envelope) != nil || envelope.Status != http.StatusOK || envelope.Data["ready"] != true || envelope.Data["uptime_seconds"] == nil || envelope.Data["active"] == nil || envelope.Data["configured"] == nil {
		t.Fatal("status response did not use the public envelope")
	}
}

func TestOpenAPIReflectsPublicContracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	contents := string(raw)
	for _, marker := range []string{"/api/qr/{id}:", "identity_name:", "authorization_codes:", "upstream_transactions:"} {
		if !strings.Contains(contents, marker) {
			t.Fatalf("OpenAPI contract is missing %q", marker)
		}
	}
}

func TestFinalProtocolPolishContracts(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/callback"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := store.applicationHandler(cfg)

	badBasic := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=authorization_code"))
	badBasic.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badBasic.SetBasicAuth("client", "wrong")
	badBasicResponse := httptest.NewRecorder()
	handler.ServeHTTP(badBasicResponse, badBasic)
	if badBasicResponse.Code != http.StatusUnauthorized || badBasicResponse.Header().Get("WWW-Authenticate") != `Basic realm="relay"` || badBasicResponse.Header().Get("Cache-Control") != "no-store" || badBasicResponse.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Basic invalid_client contract failed: %d %q", badBasicResponse.Code, badBasicResponse.Header())
	}

	queryRequest := httptest.NewRequest(http.MethodPost, "/oidc/token?code=query", strings.NewReader("grant_type=authorization_code"))
	queryRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	queryResponse := httptest.NewRecorder()
	handler.ServeHTTP(queryResponse, queryRequest)
	if queryResponse.Code != http.StatusBadRequest {
		t.Fatalf("token query parameter was accepted: %d", queryResponse.Code)
	}

	duplicateAuthorize := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=client&client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid", nil)
	duplicateAuthorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateAuthorizeResponse, duplicateAuthorize)
	if duplicateAuthorizeResponse.Code != http.StatusBadRequest {
		t.Fatalf("duplicate authorization parameter was accepted: %d", duplicateAuthorizeResponse.Code)
	}

	duplicateRequest := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=authorization_code&grant_type=authorization_code"))
	duplicateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicateRequest)
	if duplicateResponse.Code != http.StatusBadRequest {
		t.Fatalf("duplicate token parameter was accepted: %d", duplicateResponse.Code)
	}

	lookalikeRequest := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=authorization_code"))
	lookalikeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded-evil")
	lookalikeResponse := httptest.NewRecorder()
	handler.ServeHTTP(lookalikeResponse, lookalikeRequest)
	if lookalikeResponse.Code != http.StatusBadRequest || validMediaType("application/json-evil", "application/json") || !validMediaType("application/json; charset=utf-8", "application/json") {
		t.Fatalf("media-type parsing was not strict: %d", lookalikeResponse.Code)
	}

	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if unknownResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown route returned %d", unknownResponse.Code)
	}

	rootResponse := httptest.NewRecorder()
	handler.ServeHTTP(rootResponse, httptest.NewRequest(http.MethodPost, "/", nil))
	if rootResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("root wrong method returned %d", rootResponse.Code)
	}

	authErrorResponse := httptest.NewRecorder()
	handler.ServeHTTP(authErrorResponse, httptest.NewRequest(http.MethodGet, "/oauth2/missing", nil))
	if authErrorResponse.Code != http.StatusNotFound || authErrorResponse.Header().Get("Content-Security-Policy") == "" || authErrorResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("auth error security headers were incomplete: %d %q", authErrorResponse.Code, authErrorResponse.Header())
	}
}

func TestOIDCAuthorizeRateLimit(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/callback"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := store.applicationHandler(cfg)
	limited := false
	for index := range 35 {
		request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state="+strconv.Itoa(index), nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if strings.Contains(response.Header().Get("Location"), "temporarily_unavailable") {
			limited = true
			break
		}
	}

	if !limited {
		t.Fatal("OIDC authorization creation was not rate limited")
	}
}

func TestPKCEVerifierWithoutChallengeIsRejected(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/callback"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	store.authCodes["no-pkce"] = &AuthCode{Value: "no-pkce", ClientID: "client", RedirectURI: "https://client.test/callback", Sub: "subject", Email: "person@example.com", Expires: time.Now().Add(time.Minute)}
	handler := store.applicationHandler(cfg)
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {strings.Repeat("s", 32)}, "redirect_uri": {"https://client.test/callback"}, "code": {"no-pkce"}, "code_verifier": {strings.Repeat("a", 43)}}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("verifier without challenge was accepted: %d", response.Code)
	}
}

func TestFinalSecurityContracts(t *testing.T) {
	if _, err := evaluateOAuthEmail(&oauth.UserInfo{ProviderID: "subject", Email: "x@example.com", EmailVerified: false}); err == nil {
		t.Fatal("unverified email accepted")
	}

	for range 20 {
		code, err := mobileCode(3)
		if err != nil || len(code) != 14 || code[4] != '-' || code[9] != '-' {
			t.Fatalf("invalid mobile code %q: %v", code, err)
		}
	}

	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Name: "Client", Secret: "secret", RedirectURIs: []string{"https://client.test/cb"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := withBrowserRoutes(store.routes(cfg), store.loginPage(cfg), store.loginSubmit(cfg), store.enrollPage(cfg), store.errorPage("not found"))
	for _, path := range []string{"/api/logins/missing/approve", "/api/logins/missing/code"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusOK {
			t.Fatalf("action GET unexpectedly succeeded: %s", path)
		}
	}

	first := httptest.NewRecorder()
	second := httptest.NewRecorder()
	requestURL := "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&response_type=code&scope=openid"
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, requestURL, nil))
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, requestURL, nil))
	if first.Result().Cookies()[0].Name == second.Result().Cookies()[0].Name {
		t.Fatal("browser transactions share a cookie")
	}
}

func TestUserInfoRequiresExpiryAndSubject(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/callback"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := store.applicationHandler(cfg)
	for _, claims := range []jwt.MapClaims{
		{"iss": cfg.Issuer, "sub": "subject", "aud": "client", "scope": "openid", "token_use": "access"},
		{"iss": cfg.Issuer, "sub": "", "aud": "client", "scope": "openid", "token_use": "access", "exp": time.Now().Add(time.Minute).Unix()},
	} {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = oidcKeyID(store.oidc)
		raw, err := token.SignedString(store.oidc)
		if err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		request.Header.Set("Authorization", "Bearer "+raw)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("malformed access token was accepted: %d", response.Code)
		}
	}
}

func TestYAMLProductionConfig(t *testing.T) {
	values, err := keygenJSON()
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "config.yaml")
	raw := "issuer: https://relay.example.com\nlisten: 8080\ndevelopment: false\noidc_signing_key_b64: " + values["oidc_signing_key_b64"] + "\ndevice_credential_key_b64: " + values["device_credential_key_b64"] + "\noidc:\n  clients: []\noauth2:\n  providers: []\n"
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(file)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := newStore(cfg); err != nil {
		t.Fatal(err)
	}

	if err := validateSigningKeyConfiguration(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestProviderSpecificFieldsAreRejected(t *testing.T) {
	tests := []struct {
		name     string
		provider Provider
	}{
		{name: "preset scopes", provider: Provider{Provider: "google", Scopes: []string{"email"}}},
		{name: "preset issuer", provider: Provider{Provider: "github", Issuer: "https://issuer.example.com"}},
		{name: "oidc scopes", provider: Provider{Provider: "oidc", Scopes: []string{"openid"}}},
		{name: "custom issuer", provider: Provider{Provider: "custom", Issuer: "https://issuer.example.com"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateProviderFields(test.provider); err == nil {
				t.Fatal("ignored provider field was accepted")
			}
		})
	}
}

func TestLogRouteRedactsOpaqueIDs(t *testing.T) {
	tests := map[string]string{
		"/enroll/enrollment-secret":                   "/enroll/:id",
		"/api/qr/login-secret":                        "/api/qr/:id",
		"/api/enrollments/enrollment-secret/complete": "/api/enrollments/:id/complete",
		"/api/enrollments/enrollment-secret/oauth2":   "/api/enrollments/:id/oauth2",
		"/api/logins/login-secret/approve":            "/api/logins/:id/approve",
		"/login/login-secret/code":                    "/login/:id/code",
		"/oauth2/google/callback":                     "/oauth2/google/callback",
	}

	for path, expected := range tests {
		if got := logRoute(path); got != expected {
			t.Errorf("logRoute(%q) = %q, want %q", path, got, expected)
		}
	}
}

func TestSensitiveAPIRoutesDisableCaching(t *testing.T) {
	handler := noStore(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, path := range []string{"/api/enrollments", "/api/enrollments/id", "/api/logins/id/code", "/api/codes", "/api/qr/id"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
			t.Fatalf("sensitive route %s did not disable caching: %#v", path, response.Header())
		}
	}

	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/api/providers", nil))
	if public.Header().Get("Cache-Control") != "" {
		t.Fatal("public provider list unexpectedly disabled caching")
	}
}

func TestProviderDiscoveryPublishesMobileCodeCapability(t *testing.T) {
	cfg := defaults()
	cfg.MobileCode.Enabled = true
	cfg.MobileCode.Groups = 2
	cfg.OAuth2.Providers = []Provider{{ID: "google", Name: "Google", Provider: "google", ClientID: "google-client", ClientSecret: "google-secret"}}

	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	store.applicationHandler(cfg).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/providers", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("provider discovery returned %d", response.Code)
	}

	var envelope struct {
		Data struct {
			MobileCode struct {
				Enabled bool `json:"enabled"`
				Groups  int  `json:"groups"`
			} `json:"mobile_code"`
			Providers []struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			} `json:"providers"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Data.MobileCode.Enabled || envelope.Data.MobileCode.Groups != 2 {
		t.Fatalf("mobile code capability was not published: %#v", envelope.Data.MobileCode)
	}
	if len(envelope.Data.Providers) != 1 || envelope.Data.Providers[0].ID != "google" || !envelope.Data.Providers[0].Enabled {
		t.Fatalf("provider capability was not published: %#v", envelope.Data.Providers)
	}
}

func TestExpiredEnrollmentCannotComplete(t *testing.T) {
	cfg := defaults()
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	enrollment := &Enrollment{ID: "expired", State: "verified", Expires: time.Unix(100, 0), Payload: "payload", PublicKey: &key.PublicKey, Device: &Device{PublicKey: &key.PublicKey, MLDSA65PublicKey: testMLDSAKey(t).PublicKey()}}
	store.enrollmentState[enrollment.ID] = enrollment
	signature, err := ecdsa.SignASN1(rand.Reader, key, sum([]byte(enrollment.Payload)))
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.completeEnrollment(enrollment.ID, map[string]string{"p256": b64.EncodeToString(signature)}, cfg, time.Unix(101, 0))
	if !errors.Is(err, errEnrollmentExpired) || enrollment.State != "expired" {
		t.Fatalf("expired enrollment completed: state=%s err=%v", enrollment.State, err)
	}
}

func TestBrowserRouteMethods(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := withBrowserRoutes(http.NotFoundHandler(), ok, ok, ok, ok)
	tests := []struct {
		method string
		path   string
		status int
	}{
		{method: http.MethodGet, path: "/login/id", status: http.StatusOK},
		{method: http.MethodPost, path: "/login/id", status: http.StatusMethodNotAllowed},
		{method: http.MethodPost, path: "/login/id/code", status: http.StatusOK},
		{method: http.MethodGet, path: "/login/id/code", status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/enroll/id", status: http.StatusOK},
		{method: http.MethodPost, path: "/enroll/id", status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/error", status: http.StatusOK},
		{method: http.MethodPost, path: "/error", status: http.StatusMethodNotAllowed},
	}

	for _, test := range tests {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Errorf("%s %s returned %d, want %d", test.method, test.path, response.Code, test.status)
		}
	}
}

func TestAuthorizeLoginCapacityIsAtomic(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Name: "Client", Secret: strings.Repeat("s", 32), RedirectURIs: []string{"https://client.test/cb"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for index := range maxActiveLogins - 1 {
		store.loginState[fmt.Sprintf("existing-%d", index)] = &Login{}
	}

	handler := store.authorize(cfg)
	requestURL := "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&response_type=code&scope=openid"
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestURL, nil))
		})
	}

	wait.Wait()

	store.mu.RLock()
	count := len(store.loginState)
	store.mu.RUnlock()
	if count > maxActiveLogins {
		t.Fatalf("active login capacity exceeded: %d > %d", count, maxActiveLogins)
	}
}

func TestMobileCodePublicFlowAndSingleUse(t *testing.T) {
	cfg := defaults()
	cfg.MobileCode.Enabled = true
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "client", Secret: "secret", RedirectURIs: []string{"https://client.test/cb"}}}
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	handler := withBrowserRoutes(store.routes(cfg), store.loginPage(cfg), store.loginSubmit(cfg), store.enrollPage(cfg), store.errorPage("not found"))
	server := httptest.NewServer(handler)
	defer server.Close()
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pqKey := testMLDSAKey(t)
	device := &Device{UpstreamNamespace: "https://accounts.google.com", Sub: "device-sub", Email: "person@example.com", Provider: "google", UpstreamSub: "person", JTI: "mobile-jti", PublicKey: &deviceKey.PublicKey, MLDSA65PublicKey: pqKey.PublicKey()}
	credential, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{}`)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/codes", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "RelayDevice "+credential)
	signTestRequest(t, request, deviceKey, pqKey)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	var codeEnvelope struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}

	if json.NewDecoder(response.Body).Decode(&codeEnvelope) != nil || codeEnvelope.Data.Code == "" {
		t.Fatal("mobile code was not created through HTTP")
	}

	response.Body.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := server.URL + "/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&response_type=code&scope=openid"
	authResponse, _ := client.Get(authURL)
	loginURL, _ := url.Parse(authResponse.Header.Get("Location"))
	loginID := strings.TrimPrefix(loginURL.Path, "/login/")
	submit, _ := client.Post(server.URL+"/login/"+loginID+"/code", "application/x-www-form-urlencoded", strings.NewReader("code="+url.QueryEscape(codeEnvelope.Data.Code)))

	if submit.StatusCode != http.StatusFound || strings.Contains(submit.Header.Get("Location"), "/login/") {
		t.Fatal("mobile code did not complete browser login")
	}

	authResponse2, _ := client.Get(authURL)
	loginURL2, _ := url.Parse(authResponse2.Header.Get("Location"))
	submit2, _ := client.Post(server.URL+loginURL2.Path+"/code", "application/x-www-form-urlencoded", strings.NewReader("code="+url.QueryEscape(codeEnvelope.Data.Code)))
	if submit2.StatusCode != http.StatusFound || !strings.Contains(submit2.Header.Get("Location"), "/login/") {
		t.Fatal("mobile code was reusable")
	}
}

func TestMobileCodeAttemptsExpireLogin(t *testing.T) {
	store := &Store{
		loginState:  map[string]*Login{"login": {ID: "login", State: "pending", Expires: time.Now().Add(time.Minute)}},
		mobileCodes: map[string]*MobileCode{},
	}

	for attempt := 1; attempt <= maxMobileCodeAttempts; attempt++ {
		if err := store.approveLoginWithMobileCode("login", "WRONGCODE", time.Now()); err == nil {
			t.Fatal("invalid mobile code was accepted")
		}

		login := store.loginState["login"]
		if attempt < maxMobileCodeAttempts && login.State != "pending" {
			t.Fatalf("login expired too early after attempt %d", attempt)
		}
	}

	if store.loginState["login"].State != "expired" {
		t.Fatal("login remained usable after the invalid-attempt budget")
	}
}
