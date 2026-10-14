package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	relayweb "relay/web"

	"github.com/golang-jwt/jwt/v5"
)

const browserCookiePrefix = "relay_browser_"

func browserBound(r *http.Request, login *Login) bool {
	cookie, err := r.Cookie(browserCookiePrefix + login.ID)
	return err == nil && cookie.Value != "" && equalSecret(cookie.Value, login.BrowserSecret)
}

func (s *Store) routes(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/assets/", assetsHandler())
	mux.Handle("/test/", s.testPages(cfg))
	mux.Handle("/test/api/", s.testAPI(cfg))
	mux.HandleFunc("/oidc", s.demoOIDCPage(cfg))
	mux.HandleFunc("/oidc/demo/start", s.demoOIDCStart(cfg))
	mux.HandleFunc("/oidc/demo/callback", s.demoOIDCCallback(cfg))
	mux.HandleFunc("/oidc/demo/reset", s.demoOIDCReset(cfg))
	mux.Handle("/oidc/demo/", s.testAPI(cfg))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(relayweb.Favicon())
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		stats := s.statusStats()
		data := map[string]any{
			"ready":          true,
			"uptime_seconds": int(time.Since(s.startedAt).Seconds()),
			"active": map[string]int{
				"logins":                stats.logins,
				"enrollments":           stats.enrollments,
				"authorization_codes":   stats.authorizationCodes,
				"mobile_codes":          stats.mobileCodes,
				"upstream_transactions": stats.upstreamTransactions,
			},
			"configured": map[string]int{
				"oauth2_providers":     len(cfg.OAuth2.Providers),
				"oidc_relying_parties": len(cfg.OIDC.Clients),
			},
		}
		if cfg.ExposeSystemStats {
			if system := s.currentSystemStatus(); system != nil {
				data["system"] = system
			}
		}

		apiData(w, http.StatusOK, data)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		metadata := map[string]any{
			"issuer":                                cfg.Issuer,
			"authorization_endpoint":                cfg.Issuer + "/oidc/authorize",
			"userinfo_endpoint":                     cfg.Issuer + "/oidc/userinfo",
			"token_endpoint":                        cfg.Issuer + "/oidc/token",
			"jwks_uri":                              cfg.Issuer + "/oidc/jwks",
			"response_types_supported":              []string{"code"},
			"response_modes_supported":              []string{"query"},
			"grant_types_supported":                 []string{"authorization_code"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		}

		jsonOut(w, http.StatusOK, metadata)
	})

	mux.HandleFunc("/oidc/jwks", s.jwks())
	mux.HandleFunc("/api/qr/", s.qrHandler(cfg))
	mux.HandleFunc("/api/relay-qr", relayQRHandler(cfg))
	mux.HandleFunc("/api/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		providers := make([]map[string]any, 0, len(configuredProviders(cfg)))
		for _, provider := range configuredProviders(cfg) {
			providers = append(providers, map[string]any{"id": provider.ID, "name": provider.Name, "provider": provider.Provider, "enabled": true})
		}

		apiData(w, http.StatusOK, map[string]any{
			"providers": providers,
			"mobile_code": map[string]any{
				"enabled": cfg.MobileCode.Enabled,
				"groups":  cfg.MobileCode.Groups,
			},
		})
	})

	mux.HandleFunc("/api/enrollments", s.enrollmentHandler(cfg))
	mux.HandleFunc("/api/enrollments/", s.enrollmentHandler(cfg))
	mux.HandleFunc("/api/logins", s.loginHandler(cfg))
	mux.HandleFunc("/api/logins/", s.loginHandler(cfg))
	mux.HandleFunc("/api/codes", s.codeHandler(cfg))
	mux.HandleFunc("/api/watch", s.watchRegistration(cfg))
	mux.HandleFunc("/api/watch/codes", s.watchCodeHandler(cfg))
	mux.HandleFunc("/oidc/authorize", s.authorize(cfg))
	mux.HandleFunc("/oidc/userinfo", s.user(cfg))
	mux.HandleFunc("/oidc/token", s.token(cfg))
	mux.HandleFunc("/how-it-works", s.howPage(cfg))
	mux.Handle("/oauth2/", s.upstream(cfg))
	mux.HandleFunc("/", s.page(cfg))

	return mux
}

func (s *Store) applicationHandler(cfg Config) http.Handler {
	raw := withBrowserRoutes(
		s.routes(cfg),
		s.loginPage(cfg),
		s.loginSubmit(cfg),
		s.enrollPage(cfg),
		s.errorPage("The requested page could not be found."),
	)

	return requestID(securityHeaders(noStore(raw), cfg))
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := randomToken(12)
		if err != nil {
			requestID = "unavailable"
		}

		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

func logRoute(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}

	switch parts[0] {
	case "api":
		if len(parts) >= 3 && parts[1] == "qr" {
			return "/api/qr/:id"
		}
		if len(parts) >= 2 && (parts[1] == "enrollments" || parts[1] == "logins") {
			label := "/api/" + parts[1] + "/:id"
			if len(parts) >= 4 {
				label += "/" + parts[3]
			}
			return label
		}
	case "enroll":
		if len(parts) >= 2 {
			return "/enroll/:id"
		}
	case "login":
		if len(parts) >= 2 {
			label := "/login/:id"
			if len(parts) >= 3 {
				label += "/" + parts[2]
			}
			return label
		}
	case "oauth2":
		if len(parts) >= 2 {
			label := "/oauth2/" + parts[1]
			if len(parts) >= 3 && parts[2] == "callback" {
				label += "/callback"
			}
			return label
		}
	}

	return path
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sensitiveAPI := strings.HasPrefix(r.URL.Path, "/api/enrollments") || strings.HasPrefix(r.URL.Path, "/api/logins") || r.URL.Path == "/api/codes" || strings.HasPrefix(r.URL.Path, "/api/qr/") || strings.HasPrefix(r.URL.Path, "/api/watch")
		if sensitiveAPI {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}

		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/login") || strings.HasPrefix(r.URL.Path, "/enroll") || strings.HasPrefix(r.URL.Path, "/oauth2") || strings.HasPrefix(r.URL.Path, "/error") || strings.HasPrefix(r.URL.Path, "/oidc") {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		}

		next.ServeHTTP(w, r)
	})
}
func securityHeaders(next http.Handler, cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/login") || strings.HasPrefix(r.URL.Path, "/enroll") || strings.HasPrefix(r.URL.Path, "/oauth2") || strings.HasPrefix(r.URL.Path, "/error") || strings.HasPrefix(r.URL.Path, "/oidc") || r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		}

		if strings.HasPrefix(cfg.Issuer, "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Store) jwks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		raw, _ := s.oidc.PublicKey.Bytes()
		jsonOut(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(raw[1:33]), "y": b64.EncodeToString(raw[33:]), "use": "sig", "alg": "ES256", "kid": oidcKeyID(s.oidc)}}})
	}
}

func (s *Store) enrollmentHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if after, ok := strings.CutPrefix(r.URL.Path, "/api/enrollments/"); ok {
			parts := strings.Split(after, "/")
			if len(parts) > 2 || parts[0] == "" {
				errOut(w, http.StatusNotFound, "Enrollment not found.")
				return
			}

			id := parts[0]
			enrollment, ok := s.enrollmentSnapshot(id)
			if !ok {
				errOut(w, http.StatusNotFound, "Enrollment not found.")
				return
			}

			if time.Now().After(enrollment.Expires) {
				s.expireEnrollment(enrollment.ID, time.Now())
				errOut(w, http.StatusGone, "Enrollment has expired.")
				return
			}

			if len(parts) == 1 && r.Method == http.MethodGet {
				data := map[string]any{"id": enrollment.ID, "state": enrollment.State, "expires_at": enrollment.Expires.UTC().Format(time.RFC3339)}
				if enrollment.Email != "" {
					data["email"] = enrollment.Email
				}

				if enrollment.State == "verified" {
					data["signing_payload"] = enrollment.Payload
				}

				apiData(w, http.StatusOK, data)
				return
			}

			if len(parts) == 2 && parts[1] == "complete" && r.Method == http.MethodPost {
				var input struct {
					Signatures map[string]string `json:"signatures"`
				}

				if readJSON(r, &input) != nil {
					errOut(w, http.StatusBadRequest, "Invalid request.")
					return
				}

				credential, expiresAt, err := s.completeEnrollment(id, input.Signatures, cfg, time.Now())
				if err != nil {
					if strings.Contains(err.Error(), "invalid enrollment signature") {
						errOut(w, http.StatusUnauthorized, "Invalid enrollment signature.")
						return
					}

					if errors.Is(err, errEnrollmentExpired) {
						errOut(w, http.StatusGone, "Enrollment expired.")
						return
					}

					errOut(w, http.StatusConflict, "Enrollment is not ready.")
					return
				}

				data := map[string]any{"id": enrollment.ID, "state": "complete", "credential": credential, "expires_at": expiresAt.UTC().Format(time.RFC3339)}
				if enrollment.Email != "" {
					data["email"] = enrollment.Email
				}
				if enrollment.Device != nil {
					data["provider_id"] = enrollment.Device.Provider
					data["device_name"] = enrollment.Device.DeviceName
					if enrollment.Device.IdentityName != "" {
						data["identity_name"] = enrollment.Device.IdentityName
					}
				}

				apiData(w, http.StatusOK, data)
				return
			}

			if len(parts) == 2 && parts[1] == "oauth2" && r.Method == http.MethodPost {
				if !s.rateBook.allowWindow("enrollment-oauth2:"+requestIP(r, cfg.TrustCloudflareIP)+":"+id, time.Second, 6) {
					errOut(w, http.StatusTooManyRequests, "Too many authentication attempts.")
					return
				}

				var input struct {
					ProviderID string `json:"provider_id"`
				}

				if readJSON(r, &input) != nil || input.ProviderID == "" || len(input.ProviderID) > 64 {
					errOut(w, http.StatusBadRequest, "Invalid provider request.")
					return
				}

				authorizationURL, expiresAt, err := s.beginOAuth2Enrollment(r.Context(), cfg, id, input.ProviderID, time.Now())
				if err != nil {
					status := http.StatusInternalServerError
					message := "Could not start identity-provider login."
					if errors.Is(err, errEnrollmentNotFound) {
						status = http.StatusNotFound
						message = "Enrollment not found."
					}

					if errors.Is(err, errProviderNotFound) {
						status = http.StatusBadRequest
						message = "Identity provider not found."
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

					errOut(w, status, message)
					return
				}

				apiData(w, http.StatusOK, map[string]string{"authorization_url": authorizationURL, "expires_at": expiresAt.UTC().Format(time.RFC3339)})
				return
			}

			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		if r.Method != http.MethodPost {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		if !s.rateBook.allowWindow("enrollment:"+requestIP(r, cfg.TrustCloudflareIP), time.Second, 3) {
			errOut(w, http.StatusTooManyRequests, "Too many attempts.")
			return
		}

		var input struct {
			DeviceName string `json:"device_name"`
			Keys       struct {
				P256    map[string]string `json:"p256"`
				MLDSA65 string            `json:"mldsa65"`
			} `json:"keys"`
			ReturnURI string `json:"return_uri"`
		}

		if readJSON(r, &input) != nil {
			errOut(w, http.StatusBadRequest, "Invalid request.")
			return
		}

		input.DeviceName = strings.TrimSpace(input.DeviceName)
		if len([]byte(input.DeviceName)) < 1 {
			errOut(w, http.StatusBadRequest, "Device name is required.")
			return
		}

		if len([]byte(input.DeviceName)) > 128 {
			errOut(w, http.StatusBadRequest, "Device name is too long.")
			return
		}

		if err := validateEnrollmentReturnURI(input.ReturnURI, cfg.Development); err != nil {
			errOut(w, http.StatusBadRequest, "Invalid return URI.")
			return
		}

		key, err := parseJWK(input.Keys.P256)
		if err != nil {
			errOut(w, http.StatusBadRequest, "Invalid device public key.")
			return
		}

		mldsaKey, err := parseMLDSAPublicKey(input.Keys.MLDSA65)
		if err != nil {
			errOut(w, http.StatusBadRequest, "Invalid device post-quantum public key.")
			return
		}

		id, err := randomToken(18)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create enrollment.")
			return
		}

		expires := time.Now().Add(cfg.Lifetimes.Enrollment)

		s.mu.Lock()
		if len(s.enrollmentState) >= maxActiveEnrollments {
			s.mu.Unlock()
			errOut(w, http.StatusTooManyRequests, "Relay is temporarily busy.")
			return
		}

		s.enrollmentState[id] = &Enrollment{ID: id, PublicKey: key, MLDSA65PublicKey: mldsaKey, Name: input.DeviceName, ReturnURI: input.ReturnURI, Created: time.Now(), Expires: expires, State: "pending"}
		s.mu.Unlock()

		apiData(w, http.StatusCreated, map[string]string{"id": id, "state": "pending", "authorization_url": cfg.Issuer + "/enroll/" + id, "expires_at": expires.UTC().Format(time.RFC3339)})
	}
}

func (s *Store) loginHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/logins/")
		parts := strings.Split(trimmed, "/")
		if trimmed == r.URL.Path || len(parts) > 2 || parts[0] == "" {
			errOut(w, http.StatusNotFound, "Login route not found.")
			return
		}

		id, action := parts[0], ""
		if len(parts) == 2 {
			action = parts[1]
			if action == "" {
				errOut(w, http.StatusNotFound, "Login route not found.")
				return
			}
		}

		if action == "events" && r.Method == http.MethodGet {
			s.loginEvents(cfg).ServeHTTP(w, r)
			return
		}

		login, ok := s.loginSnapshot(id)
		if !ok {
			errOut(w, http.StatusNotFound, "Login not found.")
			return
		}

		if !time.Now().Before(login.Expires) && (login.State == "pending" || login.State == "approved") {
			if _, err := s.transitionLogin(id, login.State, "expired", nil); err != nil {
				slog.Debug("login expiration transition raced with another state change", "login_id", id, "error", err)
			}
			errOut(w, http.StatusGone, "Login has expired.")
			return
		}

		if action == "" && r.Method == http.MethodGet {
			apiData(w, http.StatusOK, map[string]any{
				"id":         login.ID,
				"state":      login.State,
				"client":     map[string]string{"id": login.ClientID, "name": oidcClientName(cfg, login.ClientID)},
				"scope":      login.Scope,
				"challenge":  login.Challenge,
				"expires_at": login.Expires.UTC().Format(time.RFC3339),
			})
			return
		}

		if action == "code" && r.Method == http.MethodPost {
			if !cfg.MobileCode.Enabled {
				errOut(w, http.StatusNotFound, "Login route not found.")
				return
			}

			if !browserBound(r, &login) {
				errOut(w, http.StatusNotFound, "Login not found.")
				return
			}

			if !s.rateBook.allowWindow("login-code-ip:"+requestIP(r, cfg.TrustCloudflareIP), time.Minute, 20) {
				errOut(w, http.StatusTooManyRequests, "Too many attempts.")
				return
			}

			if !s.rateBook.allowWindow("login-code:"+requestIP(r, cfg.TrustCloudflareIP)+":"+id, time.Second, 5) {
				errOut(w, http.StatusTooManyRequests, "Too many attempts.")
				return
			}

			var input struct {
				Code string `json:"code"`
			}

			if readJSON(r, &input) != nil || len(input.Code) > 32 {
				errOut(w, http.StatusBadRequest, "Invalid request.")
				return
			}

			if err := s.approveLoginWithMobileCode(id, normalizeMobileCode(input.Code), time.Now()); err != nil {
				errOut(w, http.StatusConflict, "Login is no longer pending.")
				return
			}

			apiData(w, http.StatusOK, map[string]string{"state": "approved"})
			return
		}

		if r.Method != http.MethodPost || (action != "approve" && action != "deny") {
			errOut(w, http.StatusNotFound, "Login route not found.")
			return
		}

		auth, err := s.authenticate(r, cfg)
		if err != nil {
			errOut(w, http.StatusUnauthorized, "Device authentication failed.")
			return
		}

		var input struct {
			Challenge string `json:"challenge"`
		}

		if readJSON(r, &input) != nil || len(input.Challenge) > 256 || input.Challenge != login.Challenge {
			errOut(w, http.StatusBadRequest, "Invalid login challenge.")
			return
		}

		next := "approved"
		if action == "deny" {
			next = "denied"
		}

		transitioned, err := s.transitionLogin(id, "pending", next, auth.Device)
		if err != nil {
			errOut(w, http.StatusConflict, "Login is no longer pending.")
			return
		}

		apiData(w, http.StatusOK, map[string]string{"state": transitioned})
	}
}

func (s *Store) codeHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		if !cfg.MobileCode.Enabled {
			errOut(w, http.StatusNotFound, "Code route not found.")
			return
		}

		if !s.rateBook.allowWindow("device-code:"+requestIP(r, cfg.TrustCloudflareIP), time.Second, 5) {
			errOut(w, http.StatusTooManyRequests, "Too many attempts.")
			return
		}

		auth, err := s.authenticate(r, cfg)
		if err != nil {
			errOut(w, http.StatusUnauthorized, "Device authentication failed.")
			return
		}

		var input struct{}
		if readJSON(r, &input) != nil {
			errOut(w, http.StatusBadRequest, "Invalid request.")
			return
		}

		expires := time.Now().Add(cfg.Lifetimes.Code)
		groups, err := mobileCodeGroupCount(cfg.MobileCode)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create login code.")
			return
		}

		code, err := s.createMobileCode(auth.Device, expires, groups)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create login code.")
			return
		}

		apiData(w, http.StatusCreated, map[string]any{"code": code, "groups": groups, "expires_at": expires.UTC().Format(time.RFC3339)})
	}
}

func (s *Store) authorize(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		for _, name := range []string{"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
			if len(q[name]) > 1 {
				http.Error(w, "invalid authorization request", http.StatusBadRequest)
				return
			}
		}

		client := findOIDCClient(cfg, q.Get("client_id"))
		if client == nil {
			client = demoOIDCClient(cfg, q.Get("client_id"), q.Get("redirect_uri"))
		}
		if client == nil || !contains(client.RedirectURIs, q.Get("redirect_uri")) {
			http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
			return
		}

		if len(q.Get("state")) > 1024 {
			http.Error(w, "authorization request is too large", http.StatusBadRequest)
			return
		}

		if len(q.Get("client_id")) > 256 || len(q.Get("redirect_uri")) > 2048 || len(q.Get("scope")) > 512 || len(q.Get("nonce")) > 512 {
			authorizeError(w, r, q.Get("redirect_uri"), q.Get("state"), "invalid_request", "Authorization parameter is too large.")
			return
		}

		if !s.rateBook.allowWindow("authorize:"+requestIP(r, cfg.TrustCloudflareIP)+":"+client.ID, time.Minute, 30) {
			authorizeError(w, r, q.Get("redirect_uri"), q.Get("state"), "temporarily_unavailable", "Too many authorization attempts.")
			return
		}

		redirectURI, state := q.Get("redirect_uri"), q.Get("state")
		if q.Get("response_type") != "code" {
			authorizeError(w, r, redirectURI, state, "unsupported_response_type", "Only code response_type is supported.")
			return
		}

		if mode := q.Get("response_mode"); mode != "" && mode != "query" {
			authorizeError(w, r, redirectURI, state, "invalid_request", "Only query response_mode is supported.")
			return
		}

		if !contains(strings.Fields(q.Get("scope")), "openid") {
			authorizeError(w, r, redirectURI, state, "invalid_scope", "openid scope is required.")
			return
		}

		for scope := range strings.FieldsSeq(q.Get("scope")) {
			if !contains([]string{"openid", "email", "profile"}, scope) {
				authorizeError(w, r, redirectURI, state, "invalid_scope", "Requested scope is not supported.")
				return
			}
		}

		challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
		if (challenge != "" && method != "S256") || (challenge == "" && method != "") || (client.RequirePKCE && challenge == "") || (challenge != "" && (len(challenge) < 43 || len(challenge) > 128 || !isBase64URL(challenge))) {
			authorizeError(w, r, redirectURI, state, "invalid_request", "Invalid PKCE request.")
			return
		}

		id, err := randomToken(18)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		browser, err := randomToken(32)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		challengeValue, err := randomToken(24)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		now := time.Now()
		login := &Login{ID: id, ClientID: client.ID, RedirectURI: q.Get("redirect_uri"), OAuthState: q.Get("state"), Nonce: q.Get("nonce"), Scope: strings.Join(uniqueStrings(strings.Fields(q.Get("scope"))), " "), Challenge: challengeValue, PKCE: challenge, BrowserSecret: browser, Created: now, Expires: now.Add(cfg.Lifetimes.Login), State: "pending"}

		s.mu.Lock()
		if len(s.loginState) >= maxActiveLogins {
			s.mu.Unlock()
			authorizeError(w, r, q.Get("redirect_uri"), q.Get("state"), "temporarily_unavailable", "Relay is temporarily busy.")
			return
		}

		s.loginState[id] = login
		s.mu.Unlock()
		if client.ID == demoOIDCClientID {
			s.testDemoMu.Lock()
			s.testDemoLoginID = id
			s.testDemoMu.Unlock()
		}

		http.SetCookie(w, &http.Cookie{Name: browserCookiePrefix + id, Value: browser, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(cfg.Issuer, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: int(cfg.Lifetimes.Login / time.Second)})
		http.Redirect(w, r, cfg.Issuer+"/login/"+id, http.StatusFound)
	}
}

func findOIDCClient(c Config, id string) *OIDCClient {
	for i := range c.OIDC.Clients {
		if c.OIDC.Clients[i].ID == id {
			return &c.OIDC.Clients[i]
		}
	}

	return nil
}

func oidcClientName(c Config, id string) string {
	if client := findOIDCClient(c, id); client != nil && client.Name != "" {
		return client.Name
	}

	return id
}

func humanScopes(scope string) []string {
	labels := map[string]string{
		"openid":  "Sign in",
		"email":   "Email address",
		"profile": "Profile name",
	}

	result := make([]string, 0, len(strings.Fields(scope)))
	for _, value := range strings.Fields(scope) {
		if label, ok := labels[value]; ok {
			result = append(result, label)
		}
	}

	return result
}

func contains(xs []string, x string) bool {
	return slices.Contains(xs, x)
}

func authorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "authorization request failed", http.StatusBadRequest)
		return
	}

	query := redirect.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	redirect.RawQuery = query.Encode()

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Store) token(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		if r.Method != http.MethodPost {
			jsonOut(w, http.StatusMethodNotAllowed, map[string]string{"error": "invalid_request"})
			return
		}

		if !validMediaType(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}

		critical := []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"}
		for _, name := range critical {
			if len(r.URL.Query()[name]) > 0 || len(r.PostForm[name]) > 1 {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
				return
			}
		}

		if r.PostForm.Get("grant_type") != "authorization_code" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
			return
		}

		clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		basicHeader := strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "basic ")
		if basicHeader && (clientID != "" || secret != "") {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}

		if id, value, ok := r.BasicAuth(); ok {
			clientID, secret = id, value
		}

		client := findOIDCClient(cfg, clientID)
		if client == nil {
			client = demoOIDCClient(cfg, clientID, r.PostForm.Get("redirect_uri"))
		}
		if client == nil || !equalSecret(client.Secret, secret) {
			if basicHeader {
				w.Header().Set("WWW-Authenticate", `Basic realm="relay"`)
			}

			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}

		code := r.PostForm.Get("code")
		s.mu.Lock()
		authCode := s.authCodes[code]
		verifier := r.Form.Get("code_verifier")
		verifierValid := authCode == nil || (authCode.CodeChallenge == "" && verifier == "") || (authCode.CodeChallenge != "" && isPKCEVerifier(verifier) && pkceS256(verifier) == authCode.CodeChallenge)
		valid := authCode != nil && time.Now().Before(authCode.Expires) && authCode.ClientID == client.ID && authCode.RedirectURI == r.PostForm.Get("redirect_uri") && verifierValid
		if valid {
			delete(s.authCodes, code)
		}

		s.mu.Unlock()
		if !valid {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}

		now := time.Now()
		idClaims := jwt.MapClaims{"iss": cfg.Issuer, "sub": authCode.Sub, "aud": client.ID, "iat": now.Unix(), "exp": now.Add(oidcTokenLifetime).Unix(), "token_use": "id"}
		if authCode.Nonce != "" {
			idClaims["nonce"] = authCode.Nonce
		}

		accessClaims := jwt.MapClaims{"iss": cfg.Issuer, "sub": authCode.Sub, "aud": client.ID, "scope": authCode.Scope, "iat": now.Unix(), "exp": now.Add(oidcTokenLifetime).Unix(), "token_use": "access"}
		if contains(strings.Fields(authCode.Scope), "email") {
			idClaims["email"], idClaims["email_verified"] = authCode.Email, true
			accessClaims["email"], accessClaims["email_verified"] = authCode.Email, true
		}

		if contains(strings.Fields(authCode.Scope), "profile") && authCode.IdentityName != "" {
			idClaims["name"], accessClaims["name"] = authCode.IdentityName, authCode.IdentityName
		}

		idToken, accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, idClaims), jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
		idToken.Header["kid"], accessToken.Header["kid"] = oidcKeyID(s.oidc), oidcKeyID(s.oidc)
		idRaw, idErr := idToken.SignedString(s.oidc)
		accessRaw, accessErr := accessToken.SignedString(s.oidc)

		if idErr != nil || accessErr != nil {
			jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}

		jsonOut(w, http.StatusOK, map[string]any{"access_token": accessRaw, "token_type": "Bearer", "expires_in": int(oidcTokenLifetime / time.Second), "scope": authCode.Scope, "id_token": idRaw})
	}
}

func (s *Store) user(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			jsonOut(w, http.StatusMethodNotAllowed, map[string]string{"error": "invalid_request"})
			return
		}

		if r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) > 0 {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
				return
			}
		}

		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}

		raw := parts[1]
		var claims jwt.MapClaims
		token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != "ES256" {
				return nil, errors.New("algorithm")
			}

			if t.Header["kid"] != oidcKeyID(s.oidc) {
				return nil, errors.New("key id")
			}

			return &s.oidc.PublicKey, nil
		}, jwt.WithIssuer(cfg.Issuer), jwt.WithExpirationRequired())
		sub, subOK := claims["sub"].(string)
		if err != nil || !token.Valid || !subOK || strings.TrimSpace(sub) == "" || claims["token_use"] != "access" || !clientIDClaimConfigured(cfg, claims["aud"]) || !containsClaimScope(claims["scope"], "openid") {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}

		response := map[string]any{"sub": sub}
		if containsClaimScope(claims["scope"], "email") {
			response["email"] = claims["email"]
			response["email_verified"] = true
		}

		if containsClaimScope(claims["scope"], "profile") && claims["name"] != nil {
			response["name"] = claims["name"]
		}

		jsonOut(w, http.StatusOK, response)
	}
}

func clientIDClaimConfigured(cfg Config, value any) bool {
	id, ok := value.(string)
	return ok && (findOIDCClient(cfg, id) != nil || demoOIDCClient(cfg, id, strings.TrimSuffix(cfg.Issuer, "/")+"/oidc/demo/callback") != nil)
}

func (s *Store) loginPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/login/")
		if id == "test-login" {
			s.testDemoMu.Lock()
			if s.testDemoLoginID != "" {
				id = s.testDemoLoginID
			}
			s.testDemoMu.Unlock()
		}
		login, ok := s.loginSnapshot(id)
		if !ok || !browserBound(r, &login) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if !time.Now().Before(login.Expires) && (login.State == "pending" || login.State == "approved") {
			if _, err := s.transitionLogin(id, login.State, "expired", nil); err != nil {
				slog.Debug("login expiration transition raced with another state change", "login_id", id, "error", err)
			}
			clearBrowserCookie(w, cfg, id)
			http.Redirect(w, r, oauthErrorRedirect(login.RedirectURI, login.OAuthState, "access_denied", "The login request expired."), http.StatusFound)
			return
		}

		if login.State == "approved" {
			if code, err := s.finishApproved(id); err == nil {
				clearBrowserCookie(w, cfg, id)
				http.Redirect(w, r, oauthRedirect(login.RedirectURI, code, login.OAuthState), http.StatusFound)
				return
			}
		}

		if login.State == "denied" {
			s.errorPageWithStatus("Login was denied.", http.StatusForbidden).ServeHTTP(w, r)
			return
		}

		if login.State == "completed" {
			s.errorPageWithStatus("Login has already completed.", http.StatusGone).ServeHTTP(w, r)
			return
		}

		if login.State == "expired" {
			s.errorPageWithStatus("Login has expired.", http.StatusGone).ServeHTTP(w, r)
			return
		}

		s.renderPage(w, "login", pageData{
			Title:             "Sign in",
			QRURL:             "/api/qr/" + urlPath(id),
			AppURL:            template.URL(loginQRValue(cfg.Issuer, id)),
			ID:                id,
			RelyingParty:      oidcClientName(cfg, login.ClientID),
			Scopes:            humanScopes(login.Scope),
			MobileCodeEnabled: cfg.MobileCode.Enabled,
			MobileCodeGroups:  cfg.MobileCode.Groups,
			ExpiresAt:         login.Expires.UTC().Format(time.RFC3339),
			FailureRedirect:   oauthErrorRedirect(login.RedirectURI, login.OAuthState, "access_denied", "The login request expired."),
		})
	}
}

func (s *Store) loginSubmit(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/login/"), "/code")
		login, ok := s.loginSnapshot(id)

		if !ok || !browserBound(r, &login) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if !s.rateBook.allowWindow("login-code-ip:"+requestIP(r, cfg.TrustCloudflareIP), time.Minute, 20) {
			http.Error(w, "too many code attempts", http.StatusTooManyRequests)
			return
		}

		if !s.rateBook.allowWindow("browser-code:"+requestIP(r, cfg.TrustCloudflareIP)+":"+id, time.Second, 5) {
			http.Error(w, "too many code attempts", http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if err := s.approveLoginWithMobileCode(id, normalizeMobileCode(r.Form.Get("code")), time.Now()); err != nil {
			http.Redirect(w, r, "/login/"+id, http.StatusFound)
			return
		}

		if authCode, err := s.finishApproved(id); err == nil {
			clearBrowserCookie(w, cfg, id)
			http.Redirect(w, r, oauthRedirect(login.RedirectURI, authCode, login.OAuthState), http.StatusFound)
			return
		}

		http.Redirect(w, r, "/login/"+id, http.StatusFound)
	}
}

func oauthRedirect(raw, code, state string) string {
	redirect, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	query := redirect.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}

	redirect.RawQuery = query.Encode()
	return redirect.String()
}

func oauthErrorRedirect(raw, state, code, description string) string {
	redirect, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	query := redirect.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}

	redirect.RawQuery = query.Encode()
	return redirect.String()
}

func healthcheck(rawURL string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(rawURL)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()
	var envelope struct {
		Status int `json:"status"`
		Data   struct {
			Ready bool `json:"ready"`
		} `json:"data"`
	}

	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK || envelope.Status != http.StatusOK || !envelope.Data.Ready {
		return errors.New("service is not ready")
	}

	return nil
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "healthcheck" {
		target := "http://127.0.0.1:3000/api/status"
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--url" {
				target = args[i+1]
			}
		}

		return healthcheck(target)
	}

	if len(args) > 0 && args[0] == "keygen" {
		values, err := keygenJSON()
		if err != nil {
			return err
		}

		if len(args) > 1 && args[1] == "--json" {
			raw, _ := json.Marshal(values)
			fmt.Println(string(raw))
			return nil
		}

		for _, key := range []struct {
			yamlName string
		}{
			{"oidc_signing_key_b64"},
			{"device_credential_key_b64"},
		} {
			fmt.Printf("%s: %s\n", key.yamlName, values[key.yamlName])
		}

		return nil
	}

	if len(args) > 0 && args[0] == "providers" {
		for _, name := range providerPresetNames() {
			fmt.Println(name)
		}

		return nil
	}

	if len(args) > 0 && args[0] == "check-config" {
		file := ""
		if len(args) > 1 {
			file = args[1]
		}

		cfg, err := loadConfig(file)
		if err != nil {
			return err
		}

		if err := validateSigningKeyConfiguration(cfg); err != nil {
			return err
		}

		fmt.Println("configuration valid")
		return nil
	}

	file := ""
	if len(args) > 0 {
		file = args[0]
	}

	cfg, err := loadConfig(file)
	if err != nil {
		return err
	}

	store, err := newStore(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tickerCtx, cancelTicker := context.WithCancel(ctx)
	defer cancelTicker()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				store.cleanupExpired()
			case <-tickerCtx.Done():
				return
			}
		}
	}()

	mux := store.applicationHandler(cfg)
	listenAddress := cfg.Listen
	if !strings.Contains(listenAddress, ":") {
		listenAddress = ":" + listenAddress
	}

	server := &http.Server{Addr: listenAddress, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	slog.Info("relay listening", "addr", listenAddress, "issuer", cfg.Issuer)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}
