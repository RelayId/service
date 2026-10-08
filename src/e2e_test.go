package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"crypto/mldsa"
	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
	"github.com/golang-jwt/jwt/v5"
)

func TestEndToEndEnrollThenMobileCodeLogin(t *testing.T) {
	providerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var provider *httptest.Server
	expectedNonce := ""
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "userinfo_endpoint": provider.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": pubJWK(&providerKey.PublicKey)["x"], "y": pubJWK(&providerKey.PublicKey)["y"], "kid": "mobile-provider-key", "alg": "ES256"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			claims := jwt.MapClaims{"iss": provider.URL, "sub": "mobile-subject", "aud": "mobile-client", "email": "mobile@example.com", "email_verified": true, "nonce": expectedNonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = "mobile-provider-key"
			raw, _ := token.SignedString(providerKey)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "mobile-access", "id_token": raw, "token_type": "Bearer"})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "mobile-subject", "email": "mobile@example.com", "email_verified": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	cfg := defaults()
	cfg.MobileCode.Enabled = true
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDC.Clients = []OIDCClient{{ID: "mobile-client", Secret: strings.Repeat("c", 32), RedirectURIs: []string{"https://client.example/callback"}}}
	cfg.OAuth2.Providers = []Provider{{ID: "fake-mobile", Name: "Fake Mobile", Provider: "oidc", Issuer: provider.URL, ClientID: "mobile-client", ClientSecret: strings.Repeat("p", 32), RedirectURL: "https://relay.example.com/oauth2/fake-mobile/callback"}}
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

	createBody, _ := json.Marshal(map[string]any{"device_name": "Mobile E2E", "keys": map[string]any{"p256": pubJWK(&deviceKey.PublicKey), "mldsa65": b64.EncodeToString(pqKey.PublicKey().Bytes())}})
	createResponse, err := client.Post(server.URL+"/api/enrollments", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}

	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.NewDecoder(createResponse.Body).Decode(&created)
	_ = createResponse.Body.Close()

	providersResponse, err := client.Get(server.URL + "/api/providers")
	if err != nil || providersResponse.StatusCode != http.StatusOK {
		t.Fatalf("provider listing failed: %v status=%d", err, providersResponse.StatusCode)
	}

	_ = providersResponse.Body.Close()

	startBody := bytes.NewBufferString(`{"provider_id":"fake-mobile"}`)
	start, err := client.Post(server.URL+"/api/enrollments/"+created.Data.ID+"/oauth2", "application/json", startBody)
	if err != nil {
		t.Fatal(err)
	}

	var startEnvelope struct {
		Data struct {
			AuthorizationURL string `json:"authorization_url"`
			ExpiresAt        string `json:"expires_at"`
		} `json:"data"`
	}

	if err := json.NewDecoder(start.Body).Decode(&startEnvelope); err != nil || startEnvelope.Data.AuthorizationURL == "" || startEnvelope.Data.ExpiresAt == "" {
		t.Fatalf("headless OAuth2 start response was incomplete: %v", err)
	}

	_ = start.Body.Close()
	authURL, _ := url.Parse(startEnvelope.Data.AuthorizationURL)
	expectedNonce = authURL.Query().Get("nonce")
	state := authURL.Query().Get("state")
	_ = start.Body.Close()

	callback, err := client.Get(server.URL + "/oauth2/fake-mobile/callback?state=" + url.QueryEscape(state) + "&code=mobile-code")
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("mobile enrollment callback failed: %v status=%d", err, callback.StatusCode)
	}

	_ = callback.Body.Close()

	statusResponse, err := client.Get(server.URL + "/api/enrollments/" + created.Data.ID)
	if err != nil {
		t.Fatal(err)
	}

	var status struct {
		Data struct {
			SigningPayload string `json:"signing_payload"`
		} `json:"data"`
	}

	_ = json.NewDecoder(statusResponse.Body).Decode(&status)
	_ = statusResponse.Body.Close()
	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(status.Data.SigningPayload)))
	if err != nil {
		t.Fatal(err)
	}
	mldsaSignature, err := pqKey.Sign(nil, []byte(status.Data.SigningPayload), &mldsa.Options{})
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
			Email      string `json:"email"`
		} `json:"data"`
	}

	_ = json.NewDecoder(completeResponse.Body).Decode(&completed)
	_ = completeResponse.Body.Close()
	if completed.Data.Credential == "" || completed.Data.Email != "mobile@example.com" {
		t.Fatal("mobile E2E enrollment returned no credential")
	}

	verifier := strings.Repeat("m", 43)
	authorizeQuery := url.Values{"client_id": {"mobile-client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {"openid email profile"}, "state": {"mobile-state"}, "nonce": {"mobile-nonce"}, "code_challenge": {pkceS256(verifier)}, "code_challenge_method": {"S256"}}
	authorizeResponse, err := client.Get(server.URL + "/oidc/authorize?" + authorizeQuery.Encode())
	if err != nil {
		t.Fatal(err)
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

	body := []byte(`{}`)
	codeRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/codes", bytes.NewReader(body))
	codeRequest.Header.Set("Content-Type", "application/json")
	codeRequest.Header.Set("Authorization", "RelayDevice "+completed.Data.Credential)
	signTestRequest(t, codeRequest, deviceKey, pqKey)
	codeResponse, err := client.Do(codeRequest)
	if err != nil || codeResponse.StatusCode != http.StatusCreated {
		t.Fatalf("device mobile code request failed: %v status=%d", err, codeResponse.StatusCode)
	}

	var mobileCodeResponse struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}

	_ = json.NewDecoder(codeResponse.Body).Decode(&mobileCodeResponse)
	_ = codeResponse.Body.Close()

	loginResponse, err := client.PostForm(server.URL+"/login/"+loginID+"/code", url.Values{"code": {mobileCodeResponse.Data.Code}})
	if err != nil || loginResponse.StatusCode != http.StatusFound {
		t.Fatalf("browser mobile-code completion failed: %v status=%d", err, loginResponse.StatusCode)
	}

	callbackURL, _ := url.Parse(loginResponse.Header.Get("Location"))
	_ = loginResponse.Body.Close()

	tokenResponse, err := client.PostForm(server.URL+"/oidc/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"mobile-client"}, "client_secret": {strings.Repeat("c", 32)}, "redirect_uri": {"https://client.example/callback"}, "code": {callbackURL.Query().Get("code")}, "code_verifier": {verifier}})
	if err != nil || tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("mobile token exchange failed: %v status=%d", err, tokenResponse.StatusCode)
	}

	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokens); err != nil || tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("mobile token response was incomplete: %v", err)
	}

	_ = tokenResponse.Body.Close()

	mobileSubject := hash("relay/subject\n" + provider.URL + "\nmobile-subject")
	verifyRelayIDTokenWithJWKS(t, server.URL, tokens.IDToken, "mobile-client", "mobile-nonce", cfg.Issuer, mobileSubject, "mobile@example.com")

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		userRequest, _ := http.NewRequest(method, server.URL+"/oidc/userinfo", nil)
		userRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		userResponse, requestErr := client.Do(userRequest)
		if requestErr != nil || userResponse.StatusCode != http.StatusOK {
			t.Fatalf("mobile UserInfo %s failed: %v status=%d", method, requestErr, userResponse.StatusCode)
		}

		var user struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}

		if err := json.NewDecoder(userResponse.Body).Decode(&user); err != nil || user.Sub != mobileSubject || user.Email != "mobile@example.com" || !user.EmailVerified {
			t.Fatalf("mobile UserInfo %s identity was incorrect: %#v %v", method, user, err)
		}

		_ = userResponse.Body.Close()
	}

	secondCode, _ := client.PostForm(server.URL+"/login/"+loginID+"/code", url.Values{"code": {mobileCodeResponse.Data.Code}})
	if secondCode.StatusCode == http.StatusFound && strings.Contains(secondCode.Header.Get("Location"), "client.example") {
		t.Fatal("mobile code was reusable")
	}

	_ = secondCode.Body.Close()
}

func TestOIDCRejectsNegativeClaims(t *testing.T) {
	providerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var provider *httptest.Server
	currentToken := ""
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "userinfo_endpoint": provider.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": pubJWK(&providerKey.PublicKey)["x"], "y": pubJWK(&providerKey.PublicKey)["y"], "kid": "negative-key", "alg": "ES256"}}})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "negative-access", "id_token": currentToken, "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))

	defer provider.Close()

	upstream := providers.OIDC(context.Background(), provider.URL, "negative-client", "negative-secret", []oauth.ProviderOption{
		oauth.WithInsecureURLs(),
		oauth.WithHTTPClient(provider.Client()),
		oauth.WithOIDC(oauth.OIDCConfig{Issuer: provider.URL, HTTPClient: provider.Client(), AllowInsecureURLs: true}),
	}, providers.WithProviderName("negative"), providers.WithDiscoveryHTTPClient(provider.Client()), providers.WithInsecureDiscoveryURLs())

	validClaims := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": provider.URL, "sub": "subject", "aud": "negative-client", "email": "person@example.com", "email_verified": true, "nonce": "expected", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	}

	sign := func(claims jwt.MapClaims, key *ecdsa.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "negative-key"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}

		return raw
	}

	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		key    *ecdsa.PrivateKey
	}{
		{name: "bad signature", key: func() *ecdsa.PrivateKey { key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return key }()},
		{name: "wrong issuer", mutate: func(claims jwt.MapClaims) { claims["iss"] = "https://wrong.example" }, key: providerKey},
		{name: "wrong audience", mutate: func(claims jwt.MapClaims) { claims["aud"] = "wrong-client" }, key: providerKey},
		{name: "expired", mutate: func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }, key: providerKey},
		{name: "future nbf", mutate: func(claims jwt.MapClaims) { claims["nbf"] = time.Now().Add(5 * time.Minute).Unix() }, key: providerKey},
		{name: "wrong nonce", mutate: func(claims jwt.MapClaims) { claims["nonce"] = "wrong" }, key: providerKey},
		{name: "missing nonce", mutate: func(claims jwt.MapClaims) { delete(claims, "nonce") }, key: providerKey},
		{name: "unverified email", mutate: func(claims jwt.MapClaims) { claims["email_verified"] = false }, key: providerKey},
		{name: "missing email", mutate: func(claims jwt.MapClaims) { delete(claims, "email") }, key: providerKey},
		{name: "missing subject", mutate: func(claims jwt.MapClaims) { delete(claims, "sub") }, key: providerKey},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			claims := validClaims()
			if testCase.mutate != nil {
				testCase.mutate(claims)
			}

			currentToken = sign(claims, testCase.key)
			info, err := upstream.Exchange(context.Background(), "negative-code", "https://relay.example.com/callback", "", oauth.WithExpectedNonce("expected"))
			if err == nil {
				_, err = evaluateOAuthEmail(info)
			}

			if err == nil {
				t.Fatal("invalid OIDC token was accepted")
			}
		})
	}
}

func enrollPublicCredential(t *testing.T, client *http.Client, serverURL, providerID string, expectedNonce *string) (*ecdsa.PrivateKey, *mldsa.PrivateKey, string) {
	t.Helper()

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqKey := testMLDSAKey(t)

	createBody, _ := json.Marshal(map[string]any{"device_name": "Restartable device", "keys": map[string]any{"p256": pubJWK(&deviceKey.PublicKey), "mldsa65": b64.EncodeToString(pqKey.PublicKey().Bytes())}})
	createResponse, err := client.Post(serverURL+"/api/enrollments", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}

	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	_ = json.NewDecoder(createResponse.Body).Decode(&created)
	_ = createResponse.Body.Close()

	start, err := client.Get(serverURL + "/oauth2/" + providerID + "?enrollment_id=" + url.QueryEscape(created.Data.ID))
	if err != nil {
		t.Fatal(err)
	}

	authURL, _ := url.Parse(start.Header.Get("Location"))
	*expectedNonce = authURL.Query().Get("nonce")
	state := authURL.Query().Get("state")
	_ = start.Body.Close()

	callback, err := client.Get(serverURL + "/oauth2/" + providerID + "/callback?state=" + url.QueryEscape(state) + "&code=restart-code")
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("public enrollment callback failed: %v status=%d", err, callback.StatusCode)
	}

	_ = callback.Body.Close()

	statusResponse, err := client.Get(serverURL + "/api/enrollments/" + created.Data.ID)
	if err != nil {
		t.Fatal(err)
	}

	var status struct {
		Data struct {
			SigningPayload string `json:"signing_payload"`
		} `json:"data"`
	}

	_ = json.NewDecoder(statusResponse.Body).Decode(&status)
	_ = statusResponse.Body.Close()
	signature, err := ecdsa.SignASN1(rand.Reader, deviceKey, sum([]byte(status.Data.SigningPayload)))
	if err != nil {
		t.Fatal(err)
	}
	mldsaSignature, err := pqKey.Sign(nil, []byte(status.Data.SigningPayload), &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}

	completeBody, _ := json.Marshal(map[string]any{"signatures": map[string]string{"p256": b64.EncodeToString(signature), "mldsa65": b64.EncodeToString(mldsaSignature)}})
	completeResponse, err := client.Post(serverURL+"/api/enrollments/"+created.Data.ID+"/complete", "application/json", bytes.NewReader(completeBody))
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

	return deviceKey, pqKey, completed.Data.Credential
}

func TestRestartAcceptsPreviouslyEnrolledCredential(t *testing.T) {
	providerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var provider *httptest.Server
	expectedNonce := ""
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "userinfo_endpoint": provider.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": pubJWK(&providerKey.PublicKey)["x"], "y": pubJWK(&providerKey.PublicKey)["y"], "kid": "restart-key", "alg": "ES256"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			claims := jwt.MapClaims{"iss": provider.URL, "sub": "restart-subject", "aud": "restart-client", "email": "restart@example.com", "email_verified": true, "nonce": expectedNonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = "restart-key"
			raw, _ := token.SignedString(providerKey)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "restart-access", "id_token": raw, "token_type": "Bearer"})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "restart-subject", "email": "restart@example.com", "email_verified": true})
		default:
			http.NotFound(w, r)
		}
	}))

	defer provider.Close()

	keys, err := keygenJSON()
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	cfg.Development = true
	cfg.MobileCode.Enabled = true
	cfg.Issuer = "https://relay.example.com"
	cfg.OIDCSigningKeyB64 = keys["oidc_signing_key_b64"]
	cfg.DeviceCredentialKeyB64 = keys["device_credential_key_b64"]
	cfg.OAuth2.Providers = []Provider{{ID: "restart", Name: "Restart", Provider: "oidc", Issuer: provider.URL, ClientID: "restart-client", ClientSecret: strings.Repeat("p", 32), RedirectURL: "https://relay.example.com/oauth2/restart/callback"}}

	storeA, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	serverA := httptest.NewServer(storeA.applicationHandler(cfg))
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	deviceKey, pqKey, credential := enrollPublicCredential(t, client, serverA.URL, "restart", &expectedNonce)
	serverA.Close()

	storeB, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	serverB := httptest.NewServer(storeB.applicationHandler(cfg))
	defer serverB.Close()

	body := []byte(`{}`)
	request, _ := http.NewRequest(http.MethodPost, serverB.URL+"/api/codes", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "RelayDevice "+credential)
	signTestRequest(t, request, deviceKey, pqKey)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("credential did not survive restart: %v status=%d", err, response.StatusCode)
	}

	_ = response.Body.Close()
}
