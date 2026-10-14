package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDemoAppFlowUsesRealOIDCHandlers(t *testing.T) {
	store, err := newStore(defaults())
	if err != nil {
		t.Fatal(err)
	}

	handler := store.testAPI(defaults())
	providers := httptest.NewRecorder()
	handler.ServeHTTP(providers, httptest.NewRequest(http.MethodGet, "/test/api/providers", nil))
	if providers.Code != http.StatusOK || !strings.Contains(providers.Body.String(), "Demo identity provider") {
		t.Fatalf("providers response=%d body=%s", providers.Code, providers.Body.String())
	}

	production := defaults()
	production.Development = false
	production.ServeTestPages = false
	production.Issuer = "https://relay.example.com"
	publicHandler := store.applicationHandler(production)
	publicProviders := httptest.NewRecorder()
	publicHandler.ServeHTTP(publicProviders, httptest.NewRequest(http.MethodGet, "/oidc/demo/providers", nil))
	if publicProviders.Code != http.StatusOK {
		t.Fatalf("public demo providers response=%d", publicProviders.Code)
	}
	privatePreview := httptest.NewRecorder()
	publicHandler.ServeHTTP(privatePreview, httptest.NewRequest(http.MethodGet, "/test/api/providers", nil))
	if privatePreview.Code != http.StatusNotFound {
		t.Fatalf("private preview route response=%d", privatePreview.Code)
	}

	application := store.applicationHandler(defaults())
	start := httptest.NewRecorder()
	application.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/demo/start", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("demo start response=%d location=%q", start.Code, start.Header().Get("Location"))
	}
	authorize := httptest.NewRecorder()
	application.ServeHTTP(authorize, httptest.NewRequest(http.MethodGet, start.Header().Get("Location"), nil))
	if authorize.Code != http.StatusFound || !strings.HasPrefix(authorize.Header().Get("Location"), "/login/") {
		t.Fatalf("demo authorize response=%d location=%q", authorize.Code, authorize.Header().Get("Location"))
	}
	loginURL, err := url.Parse(authorize.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeResponse := httptest.NewRecorder()
	handler.ServeHTTP(codeResponse, httptest.NewRequest(http.MethodPost, "/test/api/codes", strings.NewReader("{}")))
	if codeResponse.Code != http.StatusCreated {
		t.Fatalf("code response=%d body=%s", codeResponse.Code, codeResponse.Body.String())
	}

	var envelope struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := json.NewDecoder(codeResponse.Body).Decode(&envelope); err != nil || envelope.Data.Code == "" {
		t.Fatalf("invalid code response: %v", err)
	}

	form := url.Values{"code": {envelope.Data.Code}}
	verify := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, loginURL.Path+"/code", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range authorize.Result().Cookies() {
		request.AddCookie(cookie)
	}
	application.ServeHTTP(verify, request)
	if verify.Code != http.StatusFound || !strings.HasPrefix(verify.Header().Get("Location"), "/oidc/demo/callback?") {
		t.Fatalf("verify response=%d location=%q", verify.Code, verify.Header().Get("Location"))
	}

	callback := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, verify.Header().Get("Location"), nil)
	for _, cookie := range start.Result().Cookies() {
		callbackRequest.AddCookie(cookie)
	}
	application.ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusSeeOther || callback.Header().Get("Location") != "/oidc?verified=1" {
		t.Fatalf("demo callback response=%d location=%q", callback.Code, callback.Header().Get("Location"))
	}

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/test/api/logins/test-login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"state":"completed"`) {
		t.Fatalf("login response=%d body=%s", login.Code, login.Body.String())
	}
}
