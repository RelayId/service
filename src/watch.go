package main

import (
	"net/http"
	"strings"
	"time"
)

func (s *Store) watchRegistration(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		if !cfg.MobileCode.Enabled {
			errOut(w, http.StatusNotFound, "Watch code route not found.")
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

		token, err := randomToken(32)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create watch capability.")
			return
		}

		expiresAt := time.Now().Add(watchCapabilityLifetime)
		if auth.Device != nil && auth.Device.Exp.Before(expiresAt) {
			expiresAt = auth.Device.Exp
		}
		s.mu.Lock()
		s.watchCapabilities[token] = &WatchCapability{
			Token:     token,
			Device:    copyDevice(auth.Device),
			ExpiresAt: expiresAt,
		}
		s.mu.Unlock()

		apiData(w, http.StatusCreated, map[string]any{
			"token":      token,
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		})
	}
}

func (s *Store) watchCodeHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		if !cfg.MobileCode.Enabled {
			errOut(w, http.StatusNotFound, "Watch code route not found.")
			return
		}

		if r.URL.RawQuery != "" {
			errOut(w, http.StatusBadRequest, "Query parameters are not allowed.")
			return
		}

		if !s.rateBook.allowWindow("watch-code:"+requestIP(r, cfg.TrustCloudflareIP), time.Second, 5) {
			errOut(w, http.StatusTooManyRequests, "Too many attempts.")
			return
		}

		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "RelayWatch") || parts[1] == "" {
			errOut(w, http.StatusUnauthorized, "Watch authentication failed.")
			return
		}

		var input struct{}
		if readJSON(r, &input) != nil {
			errOut(w, http.StatusBadRequest, "Invalid request.")
			return
		}

		s.mu.RLock()
		capability := s.watchCapabilities[parts[1]]
		if capability != nil && time.Now().Before(capability.ExpiresAt) {
			capability = &WatchCapability{
				Token:     capability.Token,
				Device:    copyDevice(capability.Device),
				ExpiresAt: capability.ExpiresAt,
			}
		} else {
			capability = nil
		}
		s.mu.RUnlock()

		if capability == nil || capability.Device == nil {
			errOut(w, http.StatusUnauthorized, "Watch authentication failed.")
			return
		}

		expiresAt := time.Now().Add(cfg.Lifetimes.Code)
		groups, err := mobileCodeGroupCount(cfg.MobileCode)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create login code.")
			return
		}

		code, err := s.createMobileCode(capability.Device, expiresAt, groups)
		if err != nil {
			errOut(w, http.StatusInternalServerError, "Could not create login code.")
			return
		}

		apiData(w, http.StatusCreated, map[string]any{
			"code":       code,
			"groups":     groups,
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		})
	}
}
