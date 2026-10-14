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

		if strings.HasPrefix(path, "/test/api/logins/") {
			s.demoLoginAPI(path, r, w)
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
				"mobile_code": map[string]any{"enabled": true, "groups": 2},
			})

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
			login, ok := s.loginSnapshot(loginID)
			if !ok || login.State != "pending" || !time.Now().Before(login.Expires) {
				errOut(w, http.StatusConflict, "The demo sign-in is no longer pending.")
				return
			}
			expires := time.Now().Add(cfg.Lifetimes.Code)
			groups := 2
			code := demoMobileCode
			s.mu.Lock()
			s.mobileCodes[normalizeMobileCode(code)] = &MobileCode{
				Value:     code,
				LoginID:   loginID,
				Device:    &Device{Sub: "demo-device", Email: "demo@example.com", Provider: "demo", UpstreamNamespace: "relay:demo", UpstreamSub: "demo-user", IdentityName: "Demo User", DeviceName: "RelayId test device"},
				CreatedAt: time.Now(),
				ExpiresAt: expires,
			}
			s.mu.Unlock()
			apiData(w, http.StatusCreated, map[string]any{"code": code, "groups": groups, "expires_at": expires.UTC().Format(time.RFC3339)})

		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Store) demoLoginAPI(path string, r *http.Request, w http.ResponseWriter) {
	const prefix = "/test/api/logins/"
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, prefix), "/"), "/")
	if len(parts) < 1 || parts[0] == "" || (len(parts) > 2) || (len(parts) == 2 && parts[1] != "approve" && parts[1] != "deny") {
		http.NotFound(w, r)
		return
	}

	loginID := s.demoLoginID()
	if loginID == "" || parts[0] != loginID {
		errOut(w, http.StatusNotFound, "Demo login not found.")
		return
	}

	login, ok := s.loginSnapshot(loginID)
	if !ok {
		errOut(w, http.StatusNotFound, "Demo login not found.")
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		apiData(w, http.StatusOK, map[string]any{
			"id":         loginID,
			"state":      login.State,
			"client":     map[string]string{"id": "test-client", "name": "RelayId demo client"},
			"scope":      "openid profile email",
			"challenge":  login.Challenge,
			"expires_at": login.Expires.UTC().Format(time.RFC3339),
		})
		return
	}

	if r.Method != http.MethodPost {
		errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return
	}

	next := "approved"
	if parts[1] == "deny" {
		next = "denied"
	}
	device := &Device{Sub: "demo-device", Email: "demo@example.com", Provider: "demo", UpstreamNamespace: "relay:demo", UpstreamSub: "demo-user", IdentityName: "Demo User", DeviceName: "RelayId test device"}
	state, err := s.transitionLogin(login.ID, "pending", next, device)
	if err != nil {
		errOut(w, http.StatusConflict, "Demo login is no longer pending.")
		return
	}
	apiData(w, http.StatusOK, map[string]string{"state": state})
}

func (s *Store) demoLoginID() string {
	s.testDemoMu.Lock()
	defer s.testDemoMu.Unlock()

	return s.testDemoLoginID
}
