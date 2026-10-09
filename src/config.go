package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Issuer                 string           `yaml:"issuer"`
	Listen                 string           `yaml:"listen"`
	Development            bool             `yaml:"development"`
	ServeTestPages         bool             `yaml:"serve_test_pages"`
	ExposeSystemStats      bool             `yaml:"expose_system_stats"`
	MobileCode             MobileCodeConfig `yaml:"mobile_code"`
	TrustCloudflareIP      bool             `yaml:"trust_cloudflare_ip"`
	OIDCSigningKeyB64      string           `yaml:"oidc_signing_key_b64"`
	OIDCSigningKeyFile     string           `yaml:"oidc_signing_key_file"`
	DeviceCredentialKeyB64 string           `yaml:"device_credential_key_b64"`
	OAuth2                 OAuth2Config     `yaml:"oauth2"`
	OIDC                   OIDCConfig       `yaml:"oidc"`
	Lifetimes              Lifetimes        `yaml:"lifetimes"`
	providerEnforcement    bool
}

type OAuth2Config struct {
	Providers []Provider `yaml:"providers" json:"providers"`
}

type MobileCodeConfig struct {
	Enabled bool `yaml:"enabled"`
	Groups  int  `yaml:"groups"`
}

type OIDCConfig struct {
	Clients []OIDCClient `yaml:"clients"`
}

type OIDCClient struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	Secret       string   `yaml:"secret" json:"secret"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
	RequirePKCE  bool     `yaml:"require_pkce" json:"require_pkce"`
}

type Provider struct {
	ID               string   `yaml:"id" json:"id"`
	Name             string   `yaml:"name" json:"name"`
	Provider         string   `yaml:"provider" json:"provider"`
	Namespace        string   `yaml:"namespace" json:"namespace"`
	Issuer           string   `yaml:"issuer" json:"issuer"`
	AuthorizationURL string   `yaml:"authorization_url" json:"authorization_url"`
	TokenURL         string   `yaml:"token_url" json:"token_url"`
	UserInfoURL      string   `yaml:"userinfo_url" json:"userinfo_url"`
	Scopes           []string `yaml:"scopes" json:"scopes"`
	ClientID         string   `yaml:"client_id" json:"client_id"`
	ClientSecret     string   `yaml:"client_secret" json:"client_secret"`
	RedirectURL      string   `yaml:"-" json:"-"`
	OIDC             bool     `yaml:"-" json:"-"`
}

const maxIssuerBytes = 512

type Lifetimes struct {
	Login      time.Duration `yaml:"login"`
	Enrollment time.Duration `yaml:"enrollment"`
	Code       time.Duration `yaml:"code"`
	Credential time.Duration `yaml:"credential"`
}

func (l *Lifetimes) UnmarshalYAML(value *yaml.Node) error {
	allowed := map[string]bool{"login": true, "enrollment": true, "code": true, "credential": true}
	for index := 0; index+1 < len(value.Content); index += 2 {
		name := value.Content[index].Value
		if !allowed[name] {
			return fmt.Errorf("unknown lifetimes field %q", name)
		}
	}

	var raw struct {
		Login      string `yaml:"login"`
		Enrollment string `yaml:"enrollment"`
		Code       string `yaml:"code"`
		Credential string `yaml:"credential"`
	}

	if err := value.Decode(&raw); err != nil {
		return err
	}

	parse := func(name, value string, fallback time.Duration) (time.Duration, error) {
		if value == "" {
			return fallback, nil
		}
		parsed, err := parseFriendlyDuration(value)
		if err != nil {
			return 0, fmt.Errorf("lifetimes.%s: %w", name, err)
		}

		return parsed, nil
	}

	var err error
	if l.Login, err = parse("login", raw.Login, 5*time.Minute); err != nil {
		return err
	}

	if l.Enrollment, err = parse("enrollment", raw.Enrollment, 10*time.Minute); err != nil {
		return err
	}

	if l.Code, err = parse("code", raw.Code, time.Minute); err != nil {
		return err
	}

	if l.Credential, err = parse("credential", raw.Credential, 90*24*time.Hour); err != nil {
		return err
	}

	return nil
}

func defaults() Config {
	return Config{
		Listen:         "3000",
		Development:    true,
		ServeTestPages: true,
		MobileCode: MobileCodeConfig{
			Groups: 3,
		},
		Lifetimes: Lifetimes{
			Login:      5 * time.Minute,
			Enrollment: 10 * time.Minute,
			Code:       time.Minute,
			Credential: 90 * 24 * time.Hour,
		},
	}
}

func loadConfig(file string) (Config, error) {
	c := defaults()
	c.Development = false
	c.ServeTestPages = false

	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return c, err
		}

		decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
		decoder.KnownFields(true)
		if err = decoder.Decode(&c); err != nil {
			return c, err
		}

		c.providerEnforcement = true
	}

	issuer, err := normalizeIssuer(c.Issuer, c.Development)
	if err != nil {
		return c, err
	}

	c.Issuer = issuer
	if len([]byte(c.Issuer)) > maxIssuerBytes {
		return c, fmt.Errorf("issuer must be at most %d bytes", maxIssuerBytes)
	}

	if c.Development {
		if c.Issuer == "" {
			c.Issuer = "http://localhost:3000"
		}
	}

	seen := map[string]bool{}
	clientIDs := map[string]bool{}
	for _, client := range c.OIDC.Clients {
		if client.ID == "" || clientIDs[client.ID] {
			return c, errors.New("client IDs must be unique and non-empty")
		}

		if len([]byte(client.ID)) > 256 {
			return c, errors.New("OIDC client IDs must be at most 256 bytes")
		}

		if len([]byte(client.Name)) > 256 {
			return c, errors.New("OIDC client names must be at most 256 bytes")
		}

		if len(client.Secret) < 32 {
			return c, errors.New("OIDC client secrets must be at least 32 characters")
		}

		if len(client.RedirectURIs) == 0 {
			return c, errors.New("OIDC clients require redirect URIs")
		}

		clientIDs[client.ID] = true
	}

	for i := range c.OAuth2.Providers {
		provider := &c.OAuth2.Providers[i]
		if provider.ID == "" || seen[provider.ID] {
			return c, errors.New("provider IDs must be unique and non-empty")
		}

		if provider.Name == "" {
			return c, errors.New("providers require a display name")
		}

		if !providerIDPattern.MatchString(provider.ID) {
			return c, errors.New("provider IDs must be safe URL path identifiers")
		}

		seen[provider.ID] = true
		provider.RedirectURL = strings.TrimRight(c.Issuer, "/") + "/oauth2/" + provider.ID + "/callback"
		if provider.ClientID == "" || provider.ClientSecret == "" {
			return c, errors.New("providers require client credentials")
		}

		if !supportedProviderPreset(provider.Provider) {
			return c, fmt.Errorf("unsupported OAuth provider preset %q", provider.Provider)
		}

		if err := validateProviderFields(*provider); err != nil {
			return c, err
		}

		if provider.Provider == "custom" && !providerIDPattern.MatchString(provider.Namespace) {
			return c, errors.New("custom OAuth2 providers require a safe namespace")
		}

		if provider.Provider == "custom" && (provider.AuthorizationURL == "" || provider.TokenURL == "" || provider.UserInfoURL == "") {
			return c, errors.New("oauth2 providers require authorization_url, token_url, and userinfo_url")
		}

		if provider.Provider == "custom" {
			for _, endpoint := range []string{provider.AuthorizationURL, provider.TokenURL, provider.UserInfoURL} {
				if err := validateProviderEndpoint(endpoint, c.Development); err != nil {
					return c, err
				}
			}
		}

		if provider.Provider == "oidc" && provider.Issuer == "" {
			return c, errors.New("oidc providers require an issuer")
		}

		if provider.Provider == "oidc" {
			if err := validateProviderEndpoint(provider.Issuer, c.Development); err != nil {
				return c, err
			}

			if len([]byte(strings.TrimRight(provider.Issuer, "/"))) > maxIssuerBytes {
				return c, fmt.Errorf("oidc provider issuer must be at most %d bytes", maxIssuerBytes)
			}
		}

		if provider.Provider == "oidc" && !strings.HasPrefix(provider.Issuer, "https://") && !c.Development {
			return c, errors.New("oidc providers require an HTTPS issuer")
		}
	}

	for _, client := range c.OIDC.Clients {
		for _, redirect := range client.RedirectURIs {
			parsed, err := url.Parse(redirect)
			if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len([]byte(redirect)) > 2048 {
				return c, errors.New("OIDC redirect URIs must be absolute and fragment-free")
			}

			if !c.Development && parsed.Scheme != "https" {
				return c, errors.New("production OIDC redirect URIs must use HTTPS")
			}

			if c.Development && parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLocalHost(parsed.Hostname())) {
				return c, errors.New("development HTTP OIDC redirect URIs must use localhost, 127.0.0.1, or ::1")
			}
		}
	}

	if err := validateLifetimes(c.Lifetimes); err != nil {
		return c, err
	}

	if c.MobileCode.Groups == 0 {
		c.MobileCode.Groups = 3
	}

	if c.MobileCode.Groups < 2 || c.MobileCode.Groups > 4 {
		return c, errors.New("mobile_code.groups must be between 2 and 4")
	}

	return c, nil
}

var providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateProviderEndpoint(raw string, development bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return errors.New("OAuth provider endpoints must be absolute URLs without credentials, query, or fragment")
	}

	if parsed.Scheme != "https" && (!development || parsed.Scheme != "http" || !isLocalHost(parsed.Hostname())) {
		return errors.New("OAuth provider endpoints must use HTTPS outside local development")
	}

	return nil
}

func validateProviderFields(provider Provider) error {
	if provider.Provider == "custom" {
		if provider.Issuer != "" {
			return errors.New("custom OAuth2 providers do not accept issuer")
		}

		return nil
	}

	if provider.Provider == "oidc" {
		if provider.Namespace != "" || provider.AuthorizationURL != "" || provider.TokenURL != "" || provider.UserInfoURL != "" || len(provider.Scopes) > 0 {
			return errors.New("oidc providers only accept issuer as provider-specific configuration")
		}

		return nil
	}

	if provider.Namespace != "" || provider.Issuer != "" || provider.AuthorizationURL != "" || provider.TokenURL != "" || provider.UserInfoURL != "" || len(provider.Scopes) > 0 {
		return fmt.Errorf("provider preset %q does not accept provider-specific configuration", provider.Provider)
	}

	return nil
}

func validateSigningKeyConfiguration(cfg Config) error {
	if _, err := configuredSigningKey(cfg.OIDCSigningKeyB64, cfg.OIDCSigningKeyFile, cfg.Development); err != nil {
		return fmt.Errorf("OIDC signing key: %w", err)
	}

	if _, err := configuredCredentialKey(cfg.DeviceCredentialKeyB64, cfg.Development); err != nil {
		return fmt.Errorf("device credential key: %w", err)
	}

	return nil
}

func normalizeIssuer(raw string, development bool) (string, error) {
	if raw == "" && development {
		return "http://localhost:3000", nil
	}

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("issuer must be an absolute URL without userinfo, query, or fragment")
	}

	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("issuer must not contain a path")
	}

	if parsed.Scheme != "https" && (!development || parsed.Scheme != "http" || !isLocalHost(parsed.Hostname())) {
		return "", errors.New("issuer must use HTTPS outside local development")
	}

	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateEnrollmentReturnURI(raw string, development bool) error {
	if raw == "" {
		return nil
	}

	if len([]byte(raw)) > 2048 {
		return errors.New("return URI is too long")
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" {
		return errors.New("return URI must be an absolute URI without credentials, query, or fragment")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return nil
	}

	if scheme == "http" {
		if development && isLocalHost(parsed.Hostname()) {
			return nil
		}

		return errors.New("HTTP return URIs are only allowed for local development")
	}

	if scheme == "data" || scheme == "file" || scheme == "javascript" || scheme == "mailto" {
		return errors.New("return URI scheme is not allowed")
	}

	if !regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`).MatchString(scheme) {
		return errors.New("return URI has an invalid scheme")
	}

	return nil
}

func validateLifetimes(l Lifetimes) error {
	values := map[string]time.Duration{
		"login":      l.Login,
		"enrollment": l.Enrollment,
		"code":       l.Code,
		"credential": l.Credential,
	}

	for name, value := range values {
		if value <= 0 {
			return fmt.Errorf("duration %s must be positive", name)
		}
	}

	return nil
}

func parseFriendlyDuration(raw string) (time.Duration, error) {
	if strings.HasSuffix(raw, "d") || strings.HasSuffix(raw, "w") {
		unit := time.Hour * 24
		value := strings.TrimSuffix(raw, "d")
		if strings.HasSuffix(raw, "w") {
			unit *= 7
			value = strings.TrimSuffix(raw, "w")
		}

		if value == "" {
			return 0, errors.New("duration unit requires a positive integer")
		}

		var count int64
		if _, err := fmt.Sscanf(value, "%d", &count); err != nil || count <= 0 || fmt.Sprintf("%d", count) != value {
			return 0, errors.New("day and week units require a positive integer")
		}

		return time.Duration(count) * unit, nil
	}

	return time.ParseDuration(raw)
}
