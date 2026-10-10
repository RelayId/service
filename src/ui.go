package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	relayweb "relay/web"
)

type pageData struct {
	Title             string
	Heading           string
	Message           string
	EnrollmentID      string
	State             string
	DeviceName        string
	QRURL             string
	AppURL            template.URL
	ID                string
	Providers         []pageProvider
	Preview           bool
	RelyingParty      string
	Scopes            []string
	MobileCodeEnabled bool
	MobileCodeGroups  int
	ExpiresAt         string
	FailureRedirect   string
	RelayURL          template.URL
}

type pageProvider struct {
	Name     string
	URL      string
	Disabled bool
}

var pageTemplates = map[string]*template.Template{
	"home":   template.Must(template.ParseFS(relayweb.Files, "templates/base.html", "templates/home.html")),
	"how":    template.Must(template.ParseFS(relayweb.Files, "templates/base.html", "templates/how.html")),
	"login":  template.Must(template.ParseFS(relayweb.Files, "templates/base.html", "templates/login.html")),
	"enroll": template.Must(template.ParseFS(relayweb.Files, "templates/base.html", "templates/enroll.html")),
	"error":  template.Must(template.ParseFS(relayweb.Files, "templates/base.html", "templates/error.html")),
}

func (s *Store) renderPage(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates, ok := pageTemplates[name]
	if !ok {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	if err := templates.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Store) enrollPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" {
			s.enrollmentDetailPage(cfg).ServeHTTP(w, r)
			return
		}

		s.renderPage(w, "enroll", pageData{Title: "Start enrollment", Heading: "Start enrollment from the RelayId app", Message: "Open the RelayId app, choose Add device, and follow the enrollment link it opens here. This page cannot start an enrollment by itself."})
	}
}

func (s *Store) enrollmentDetailPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/enroll/")
		enrollment, ok := s.enrollmentSnapshot(id)
		if !ok {
			s.errorPageWithStatus("Enrollment not found or expired.", http.StatusNotFound).ServeHTTP(w, r)
			return
		}

		if !time.Now().Before(enrollment.Expires) {
			s.expireEnrollment(enrollment.ID, time.Now())
			s.errorPageWithStatus("Enrollment has expired.", http.StatusGone).ServeHTTP(w, r)
			return
		}

		providers := make([]pageProvider, 0, len(cfg.OAuth2.Providers))
		if enrollment.State == "pending" {
			for _, provider := range cfg.OAuth2.Providers {
				providers = append(providers, pageProvider{Name: provider.Name, URL: "/oauth2/" + urlPath(provider.ID) + "?enrollment_id=" + urlQuery(enrollment.ID)})
			}
		}

		message := "Continue with a configured identity provider to verify the account, then return to the app."
		if enrollment.State == "verified" {
			message = "Identity verified. Return to the Relay app to finish enrollment."
		}

		if enrollment.State == "complete" {
			message = "Enrollment complete."
		}

		s.renderPage(w, "enroll", pageData{Title: "Authorize device", Heading: "Authorize this device", Message: message, EnrollmentID: enrollment.ID, State: enrollment.State, DeviceName: enrollment.Name, Providers: providers})
	}
}

func (s *Store) errorPage(message string) http.HandlerFunc {
	return s.errorPageWithStatus(message, http.StatusNotFound)
}

func (s *Store) errorPageWithStatus(message string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		s.renderPage(w, "error", pageData{Title: "RelayId error", Message: message})
	}
}

func clearBrowserCookie(w http.ResponseWriter, cfg Config, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     browserCookiePrefix + id,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(cfg.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Store) page(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		s.renderPage(w, "home", pageData{Title: "RelayId", MobileCodeEnabled: cfg.MobileCode.Enabled, RelayURL: template.URL(relayQRValue(cfg.Issuer))})
	}
}

func (s *Store) howPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/how-it-works" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		s.renderPage(w, "how", pageData{Title: "How it works"})
	}
}

func (s *Store) testPages(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.ServeTestPages {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		switch r.URL.Path {
		case "/test/enroll":
			s.renderPage(w, "enroll", pageData{Title: "Start enrollment", Heading: "Start enrollment from the RelayId app", Message: "Open the RelayId app, choose Add device, and follow the enrollment link it opens here. This page cannot start an enrollment by itself."})
		case "/test/enroll/preview-enrollment":
			state := r.URL.Query().Get("state")
			if state != "verified" && state != "complete" {
				state = "pending"
			}

			message := "Continue with a configured identity provider to verify the account, then return to the app."
			if state == "verified" {
				message = "Identity verified. Your Relay app is completing enrollment.."
			}
			if state == "complete" {
				message = "Your Relay app finished enrollment successfully."
			}

			providers := []pageProvider(nil)
			if state == "pending" {
				providers = []pageProvider{{Name: "Google", Disabled: true}}
			}

			s.renderPage(w, "enroll", pageData{
				Title:        "Authorize device",
				Heading:      "Authorize this device",
				Message:      message,
				EnrollmentID: "preview-enrollment",
				State:        state,
				DeviceName:   "Office laptop",
				Providers:    providers,
				Preview:      true,
			})
		case "/test/login":
			mobileCodeEnabled := cfg.MobileCode.Enabled
			mobileCodeGroups := cfg.MobileCode.Groups
			switch strings.ToLower(r.URL.Query().Get("mobile_code")) {
			case "1", "true", "on", "yes":
				mobileCodeEnabled = true
			case "0", "false", "off", "no":
				mobileCodeEnabled = false
			}
			if requestedGroups, err := strconv.Atoi(r.URL.Query().Get("groups")); err == nil && requestedGroups >= 2 && requestedGroups <= 4 {
				mobileCodeGroups = requestedGroups
			}

			s.renderPage(w, "login", pageData{
				Title:             "Sign in",
				QRURL:             "/test/qr",
				AppURL:            template.URL(loginQRValue(cfg.Issuer, "preview-login")),
				ID:                "preview-login",
				RelyingParty:      "Example relying party",
				Scopes:            []string{"Sign in", "Email address", "Profile name"},
				MobileCodeEnabled: mobileCodeEnabled,
				MobileCodeGroups:  mobileCodeGroups,
			})
		case "/test/error":
			s.errorPageWithStatus("This is an example error page.", http.StatusBadRequest).ServeHTTP(w, r)
		case "/test/qr":
			image, err := qrPNG(cfg.Issuer + "/test/login")
			if err != nil {
				http.Error(w, "could not render QR", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(image)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Store) loginEvents(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/logins/"), "/events")
		login, ok := s.loginSnapshot(id)
		if !ok || !browserBound(r, &login) {
			errOut(w, http.StatusNotFound, "Login not found")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			errOut(w, http.StatusInternalServerError, "Streaming unavailable")
			return
		}

		controller := http.NewResponseController(w)
		_ = controller.SetWriteDeadline(time.Time{})

		deadline := time.NewTimer(cfg.Lifetimes.Login)
		ticker := time.NewTicker(500 * time.Millisecond)
		heartbeat := time.NewTicker(15 * time.Second)
		defer deadline.Stop()
		defer ticker.Stop()
		defer heartbeat.Stop()
		last := ""
		for {
			login, ok := s.loginSnapshot(id)
			if !ok || !browserBound(r, &login) {
				return
			}

			state := login.State
			if time.Now().After(login.Expires) {
				state = "expired"
			}
			if state != last {
				payload := "{}"
				if state == "expired" {
					encoded, err := json.Marshal(map[string]string{"redirect": oauthErrorRedirect(login.RedirectURI, login.OAuthState, "access_denied", "The login request expired.")})
					if err == nil {
						payload = string(encoded)
					}
				}

				_, _ = w.Write([]byte("event: " + state + "\ndata: " + payload + "\n\n"))
				flusher.Flush()
				last = state
			}

			if state == "approved" || state == "completed" || state == "denied" || state == "expired" {
				return
			}

			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
			case <-heartbeat.C:
				_, _ = w.Write([]byte(": keepalive\n\n"))
				flusher.Flush()
			}
		}
	})
}

func assetsHandler() http.Handler {
	staticFS, err := relayweb.StaticFS()
	if err != nil {
		panic(err)
	}

	return http.StripPrefix("/assets/", http.FileServer(http.FS(staticFS)))
}

func withBrowserRoutes(next http.Handler, login, submit, enroll http.Handler, errorHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/login/"):
			if strings.HasSuffix(r.URL.Path, "/code") && r.Method == http.MethodPost {
				submit.ServeHTTP(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/code") || r.Method != http.MethodGet {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			} else {
				login.ServeHTTP(w, r)
			}
		case r.URL.Path == "/enroll" || strings.HasPrefix(r.URL.Path, "/enroll/"):
			if r.Method != http.MethodGet {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			} else {
				enroll.ServeHTTP(w, r)
			}
		case r.URL.Path == "/error":
			if r.Method != http.MethodGet {
				errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			} else {
				errorHandler.ServeHTTP(w, r)
			}
		default:
			next.ServeHTTP(w, r)
		}
	})
}
