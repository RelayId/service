package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWatchCapabilityIssuesScopedCode(t *testing.T) {
	cfg := defaults()
	cfg.MobileCode.Enabled = true
	store, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)
	device := &Device{
		UpstreamNamespace: "https://accounts.example",
		Sub:               "subject",
		Email:             "person@example.com",
		Provider:          "provider",
		UpstreamSub:       "upstream-subject",
		JTI:               "watch-device",
		PublicKey:         &p256Key.PublicKey,
		MLDSA65PublicKey:  pqKey.PublicKey(),
	}
	credential, err := store.signCredential(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	registration := httptest.NewRequest(http.MethodPost, "/api/watch", bytes.NewReader([]byte(`{}`)))
	registration.Header.Set("Content-Type", "application/json")
	registration.Header.Set("Authorization", "RelayDevice "+credential)
	registrationResponse := httptest.NewRecorder()
	store.watchRegistration(cfg).ServeHTTP(registrationResponse, registration)
	if registrationResponse.Code != http.StatusCreated {
		t.Fatalf("watch registration status = %d, want %d", registrationResponse.Code, http.StatusCreated)
	}

	var registrationBody struct {
		Data struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(registrationResponse.Body).Decode(&registrationBody); err != nil {
		t.Fatal(err)
	}
	if registrationBody.Data.Token == "" || registrationBody.Data.ExpiresAt == "" {
		t.Fatal("watch registration did not return a token and expiry")
	}

	watchRequest := httptest.NewRequest(http.MethodPost, "/api/watch/codes", strings.NewReader(`{}`))
	watchRequest.Header.Set("Content-Type", "application/json")
	watchRequest.Header.Set("Authorization", "RelayWatch "+registrationBody.Data.Token)
	watchResponse := httptest.NewRecorder()
	store.watchCodeHandler(cfg).ServeHTTP(watchResponse, watchRequest)
	if watchResponse.Code != http.StatusCreated {
		t.Fatalf("watch code status = %d, want %d", watchResponse.Code, http.StatusCreated)
	}

	var codeBody struct {
		Data struct {
			Code      string `json:"code"`
			Groups    int    `json:"groups"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(watchResponse.Body).Decode(&codeBody); err != nil {
		t.Fatal(err)
	}
	if codeBody.Data.Code == "" || codeBody.Data.Groups != cfg.MobileCode.Groups || codeBody.Data.ExpiresAt == "" {
		t.Fatalf("watch code response was incomplete: %+v", codeBody.Data)
	}

	store.mu.Lock()
	store.watchCapabilities[registrationBody.Data.Token].ExpiresAt = time.Now().Add(-time.Second)
	store.mu.Unlock()
	expiredRequest := httptest.NewRequest(http.MethodPost, "/api/watch/codes", strings.NewReader(`{}`))
	expiredRequest.Header.Set("Content-Type", "application/json")
	expiredRequest.Header.Set("Authorization", "RelayWatch "+registrationBody.Data.Token)
	expiredResponse := httptest.NewRecorder()
	store.watchCodeHandler(cfg).ServeHTTP(expiredResponse, expiredRequest)
	if expiredResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expired watch capability status = %d, want %d", expiredResponse.Code, http.StatusUnauthorized)
	}
}
