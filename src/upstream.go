package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JLugagne/egauth/oauth"
)

var (
	errEnrollmentNotFound = errors.New("enrollment not found or expired")
	errEnrollmentExpired  = errors.New("enrollment expired")
	errEnrollmentConflict = errors.New("enrollment is no longer pending")
	errProviderNotFound   = errors.New("identity provider not found")
	errOAuthUnavailable   = errors.New("provider type is not supported")
	errProviderTemporary  = errors.New("provider is temporarily unavailable")
	errStateCapacity      = errors.New("temporary state capacity reached")
)

func findProvider(cfg Config, id string) *Provider {
	for index := range cfg.OAuth2.Providers {
		if cfg.OAuth2.Providers[index].ID == id {
			return &cfg.OAuth2.Providers[index]
		}
	}

	return nil
}

func (s *Store) upstream(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.errorPageWithStatus("Method not allowed.", http.StatusMethodNotAllowed).ServeHTTP(w, r)
			return
		}

		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/oauth2/"), "/")
		if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] != "callback") {
			s.errorPageWithStatus("Identity provider route not found.", http.StatusNotFound).ServeHTTP(w, r)
			return
		}

		provider := findProvider(cfg, parts[0])
		if provider == nil {
			s.errorPageWithStatus("Identity provider not found.", http.StatusNotFound).ServeHTTP(w, r)
			return
		}

		if !s.rateBook.allowWindow("upstream:"+requestIP(r, cfg.TrustCloudflareIP)+":"+provider.ID, time.Second, 6) {
			s.errorPageWithStatus("Too many authentication attempts.", http.StatusTooManyRequests).ServeHTTP(w, r)
			return
		}

		if len(parts) == 2 {
			s.upstreamCallback(cfg, *provider, w, r)
			return
		}

		authorizationURL, _, err := s.beginOAuth2Enrollment(r.Context(), cfg, r.URL.Query().Get("enrollment_id"), provider.ID, time.Now())
		if err != nil {
			s.oauthStartError(err).ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, authorizationURL, http.StatusTemporaryRedirect)
	})
}

func (s *Store) beginOAuth2Enrollment(ctx context.Context, cfg Config, enrollmentID, providerID string, now time.Time) (string, time.Time, error) {
	enrollment, ok := s.enrollmentSnapshot(enrollmentID)
	if !ok {
		return "", time.Time{}, errEnrollmentNotFound
	}

	if !now.Before(enrollment.Expires) {
		s.expireEnrollment(enrollment.ID, now)
		return "", time.Time{}, errEnrollmentExpired
	}

	if enrollment.State != "pending" {
		return "", time.Time{}, errEnrollmentConflict
	}

	provider := findProvider(cfg, providerID)
	if provider == nil {
		return "", time.Time{}, errProviderNotFound
	}

	upstream, err := s.getUpstreamProvider(ctx, cfg, *provider)
	if err != nil {
		if provider.Provider == "oidc" {
			return "", time.Time{}, errProviderTemporary
		}

		return "", time.Time{}, errOAuthUnavailable
	}

	state, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}

	verifier, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}

	nonce, err := randomToken(24)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := now.Add(upstreamOAuthStateLifetime)
	s.mu.Lock()
	if len(s.upstreamStates) >= maxUpstreamStates {
		s.mu.Unlock()
		return "", time.Time{}, errStateCapacity
	}

	s.upstreamStates[state] = &UpstreamState{Value: state, EnrollmentID: enrollmentID, ProviderID: provider.ID, Nonce: nonce, Verifier: verifier, ExpiresAt: expiresAt}
	s.mu.Unlock()

	authOptions := []oauth.AuthCodeOption{}
	if providerUsesOIDC(*provider) {
		authOptions = append(authOptions, oauth.WithAuthNonce(nonce))
	}

	authURL := upstream.AuthCodeURL(state, provider.RedirectURL, pkceS256(verifier), authOptions...)
	if authURL == "" {
		s.mu.Lock()
		delete(s.upstreamStates, state)
		s.mu.Unlock()

		return "", time.Time{}, errors.New("provider configuration is invalid")
	}

	return authURL, expiresAt, nil
}

func (s *Store) oauthStartError(err error) http.Handler {
	status := http.StatusInternalServerError
	message := "Could not start identity-provider login."
	if errors.Is(err, errEnrollmentNotFound) || errors.Is(err, errProviderNotFound) {
		status = http.StatusNotFound
		message = "Enrollment or identity provider not found."
	}

	if errors.Is(err, errEnrollmentExpired) {
		status = http.StatusGone
		message = "Enrollment has expired."
	}

	if errors.Is(err, errEnrollmentConflict) {
		status = http.StatusConflict
		message = "Enrollment is no longer pending."
	}

	if errors.Is(err, errOAuthUnavailable) {
		status = http.StatusBadRequest
		message = "Provider type is not supported."
	}

	if errors.Is(err, errProviderTemporary) {
		status = http.StatusServiceUnavailable
		message = "Identity provider is temporarily unavailable."
	}

	if errors.Is(err, errStateCapacity) {
		status = http.StatusTooManyRequests
		message = "Relay is temporarily busy."
	}

	return s.errorPageWithStatus(message, status)
}

func (s *Store) upstreamCallback(cfg Config, provider Provider, w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for _, name := range []string{"state", "code", "error", "error_description", "iss"} {
		if len(query[name]) > 1 {
			s.errorPageWithStatus("The identity-provider response was invalid.", http.StatusBadRequest).ServeHTTP(w, r)
			return
		}
	}

	state := query.Get("state")
	s.mu.Lock()
	upstreamState := s.upstreamStates[state]
	if upstreamState != nil {
		delete(s.upstreamStates, state)
	}

	s.mu.Unlock()
	if upstreamState == nil || upstreamState.ProviderID != provider.ID || time.Now().After(upstreamState.ExpiresAt) {
		s.errorPageWithStatus("The identity-provider session expired.", http.StatusGone).ServeHTTP(w, r)
		return
	}

	if query.Get("error") != "" {
		s.errorPageWithStatus("The identity-provider login was not approved.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	if query.Get("code") == "" {
		s.errorPageWithStatus("The identity-provider response was invalid.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	enrollment, ok := s.enrollmentSnapshot(upstreamState.EnrollmentID)
	if !ok || time.Now().After(enrollment.Expires) {
		s.errorPageWithStatus("Enrollment not found or expired.", http.StatusNotFound).ServeHTTP(w, r)
		return
	}

	upstream, err := s.getUpstreamProvider(r.Context(), cfg, provider)
	if err != nil {
		if provider.Provider == "oidc" {
			s.errorPageWithStatus("Identity provider is temporarily unavailable.", http.StatusServiceUnavailable).ServeHTTP(w, r)
			return
		}

		s.errorPageWithStatus("Provider type is not supported.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	if !validOAuthResponseIssuer(upstream, query) {
		s.errorPageWithStatus("The identity-provider response was invalid.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	options := []oauth.ExchangeOption{}
	if providerUsesOIDC(provider) {
		options = append(options, oauth.WithExpectedNonce(upstreamState.Nonce))
	}

	user, err := upstream.Exchange(r.Context(), query.Get("code"), provider.RedirectURL, upstreamState.Verifier, options...)
	if err != nil {
		slog.Warn("upstream identity exchange failed", "provider", provider.ID, "stage", "exchange", "error", err)
		s.errorPageWithStatus("The identity provider did not provide a usable email.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	email, err := evaluateOAuthEmail(user)
	if err != nil {
		slog.Warn("upstream identity email rejected", "provider", provider.ID, "stage", "email", "error", err)
		s.errorPageWithStatus("The identity provider did not provide a usable email.", http.StatusBadRequest).ServeHTTP(w, r)
		return
	}

	if err := s.finishEnrollment(&enrollment, provider.ID, providerNamespace(provider), user.ProviderID, email, user.Name); err != nil {
		s.errorPageWithStatus("Could not complete enrollment.", http.StatusConflict).ServeHTTP(w, r)
		return
	}

	if enrollment.ReturnURI != "" {
		if redirectURI, err := appendEnrollmentReturn(enrollment.ReturnURI, enrollment.ID); err == nil {
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, cfg.Issuer+"/enroll/"+enrollment.ID, http.StatusFound)
}

func appendEnrollmentReturn(raw, enrollmentID string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	query.Set("enrollment_id", enrollmentID)
	query.Set("state", "verified")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validOAuthResponseIssuer(upstream *oauth.Provider, query url.Values) bool {
	if len(query["iss"]) > 1 {
		return false
	}

	iss := query.Get("iss")
	return iss == "" || upstream.ValidateIssuer(iss)
}

func configureOAuth(cfg Config) (map[string]*oauth.Provider, error) {
	configured := make(map[string]*oauth.Provider, len(cfg.OAuth2.Providers))
	for _, provider := range cfg.OAuth2.Providers {
		if provider.Provider == "oidc" {
			continue
		}

		value, err := newOAuthProvider(context.Background(), provider, cfg.Development)
		if err != nil {
			return nil, err
		}

		if value.AuthCodeURL("configuration-check", provider.RedirectURL, "") == "" {
			return nil, fmt.Errorf("provider %q has invalid OAuth endpoint or discovery configuration", provider.ID)
		}

		configured[provider.ID] = value
	}

	return configured, nil
}

func (s *Store) getUpstreamProvider(ctx context.Context, cfg Config, provider Provider) (*oauth.Provider, error) {
	s.upstreamProviderMu.Lock()
	slot := s.upstreamProviderSlots[provider.ID]
	if slot == nil {
		slot = &upstreamProviderSlot{}
		s.upstreamProviderSlots[provider.ID] = slot
	}

	s.upstreamProviderMu.Unlock()

	slot.mu.Lock()
	defer slot.mu.Unlock()

	if slot.provider != nil {
		return slot.provider, nil
	}

	value, err := newOAuthProvider(ctx, provider, cfg.Development)
	if err != nil {
		return nil, err
	}

	if value.AuthCodeURL("configuration-check", provider.RedirectURL, "") == "" {
		return nil, fmt.Errorf("provider %q has invalid OAuth endpoint or discovery configuration", provider.ID)
	}

	slot.provider = value
	return value, nil
}

func providerUsesOIDC(provider Provider) bool {
	return provider.Provider == "oidc" || provider.Provider == "google" || provider.Provider == "gitlab" || provider.Provider == "linkedin"
}

func providerNamespace(provider Provider) string {
	switch provider.Provider {
	case "google", "github", "discord", "gitlab", "linkedin":
		return "relay:oauth2:" + provider.Provider
	case "custom":
		return provider.Namespace
	}

	if strings.TrimSpace(provider.Issuer) != "" {
		return strings.TrimRight(provider.Issuer, "/")
	}

	return provider.ID
}

func (s *Store) finishEnrollment(enrollment *Enrollment, providerID, upstreamNamespace, upstreamSub, email, identityName string) error {
	jti, err := randomToken(18)
	if err != nil {
		return err
	}

	device := &Device{Email: strings.ToLower(email), UpstreamNamespace: upstreamNamespace, Provider: providerID, UpstreamSub: upstreamSub, Sub: hash("relay/device\n" + providerID + "\n" + upstreamSub), JTI: jti, DeviceName: enrollment.Name, IdentityName: strings.TrimSpace(identityName), PublicKey: enrollment.PublicKey, MLDSA65PublicKey: enrollment.MLDSA65PublicKey}
	payload, err := enrollmentSigningPayload(enrollment, device)
	if err != nil {
		return err
	}

	return s.verifyEnrollment(enrollment.ID, device, device.Email, payload, time.Now())
}

func enrollmentSigningPayload(enrollment *Enrollment, device *Device) (string, error) {
	key, _ := json.Marshal(pubJWK(device.PublicKey))
	challenge, err := randomToken(24)
	if err != nil {
		return "", err
	}

	return "relay-enrollment\n" + enrollment.ID + "\n" + device.Provider + "\n" + device.UpstreamSub + "\n" + device.Email + "\n" + string(key) + "\n" + encodeMLDSAPublicKey(device.MLDSA65PublicKey) + "\n" + enrollment.Expires.UTC().Format(time.RFC3339Nano) + "\n" + challenge, nil
}
