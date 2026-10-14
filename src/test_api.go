package main

import (
	"net/http"
	"strings"
	"time"
)

func (s *Store) testAPI(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		publicDemo := strings.HasPrefix(path, "/oidc/demo/")
		if publicDemo {
			path = strings.Replace(path, "/oidc/demo/", "/test/api/", 1)
		}

		if !cfg.ServeTestPages && !publicDemo {
			http.NotFound(w, r)
			return
		}

		switch path {
		case "/test/api/providers":
			if r.Method != http.MethodGet {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
				return
			}

			apiData(w, http.StatusOK, map[string]any{
				"providers":   []map[string]any{{"id": "demo", "name": "Demo identity provider", "provider": "demo", "enabled": true}},
				"mobile_code": map[string]any{"enabled": true, "groups": 3},
			})

		case "/test/api/logins/test-login":
			if r.Method != http.MethodGet {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
				return
			}

			loginID := s.demoLoginID()
			login, ok := s.loginSnapshot(loginID)
			if !ok {
				errOut(w, http.StatusNotFound, "Demo login not found.")
				return
			}
			apiData(w, http.StatusOK, map[string]any{
				"id":         "test-login",
				"state":      login.State,
				"client":     map[string]string{"id": "test-client", "name": "RelayId demo client"},
				"scope":      "openid profile email",
				"challenge":  login.Challenge,
				"expires_at": login.Expires.UTC().Format(time.RFC3339),
			})

		case "/test/api/logins/test-login/approve", "/test/api/logins/test-login/deny":
			if r.Method != http.MethodPost {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
				return
			}

			loginID := s.demoLoginID()
			login, ok := s.loginSnapshot(loginID)
			if !ok {
				errOut(w, http.StatusNotFound, "Demo login not found.")
				return
			}
			next := "approved"
			if strings.HasSuffix(path, "/deny") {
				next = "denied"
			}
			device := &Device{Sub: "demo-device", Email: "demo@example.com", Provider: "demo", UpstreamNamespace: "relay:demo", UpstreamSub: "demo-user", IdentityName: "Demo User", DeviceName: "RelayId test device"}
			state, err := s.transitionLogin(login.ID, "pending", next, device)
			if err != nil {
				errOut(w, http.StatusConflict, "Demo login is no longer pending.")
				return
			}
			apiData(w, http.StatusOK, map[string]string{"state": state})

		case "/test/api/codes":
			if r.Method != http.MethodPost {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
				return
			}

			loginID := s.demoLoginID()
			if loginID == "" {
				errOut(w, http.StatusConflict, "Start the demo sign-in first.")
				return
			}
			expires := time.Now().Add(cfg.Lifetimes.Code)
			groups := 3
			code, err := s.createMobileCode(&Device{Sub: "demo-device", Email: "demo@example.com", Provider: "demo", UpstreamNamespace: "relay:demo", UpstreamSub: "demo-user", IdentityName: "Demo User", DeviceName: "RelayId test device"}, expires, groups)
			if err != nil {
				errOut(w, http.StatusInternalServerError, "Could not create demo login code.")
				return
			}
			apiData(w, http.StatusCreated, map[string]any{"code": code, "groups": groups, "expires_at": expires.UTC().Format(time.RFC3339)})

		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Store) demoLoginID() string {
	s.testDemoMu.Lock()
	defer s.testDemoMu.Unlock()

	return s.testDemoLoginID
}
