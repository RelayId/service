package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/oauth/providers"
)

var providerHTTPClient = &http.Client{Timeout: 12 * time.Second}

type providerFactory func(Provider, bool) (*oauth.Provider, error)

var providerFactories = map[string]providerFactory{
	"custom":   newCustomProvider,
	"discord":  newDiscordProvider,
	"github":   newGitHubProvider,
	"gitlab":   newGitLabProvider,
	"google":   newGoogleProvider,
	"linkedin": newLinkedInProvider,
}

func supportedProviderPreset(name string) bool {
	if name == "oidc" {
		return true
	}

	_, ok := providerFactories[name]
	return ok
}

func providerPresetNames() []string {
	names := make([]string, 0, len(providerFactories)+1)
	for name := range providerFactories {
		names = append(names, name)
	}
	names = append(names, "oidc")
	sort.Strings(names)
	return names
}

func newOAuthProvider(ctx context.Context, config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	if config.Provider == "oidc" {
		return newOIDCProvider(ctx, config, allowInsecureURLs)
	}

	factory, ok := providerFactories[config.Provider]
	if !ok {
		return nil, fmt.Errorf("unsupported OAuth provider preset %q", config.Provider)
	}

	return factory(config, allowInsecureURLs)
}

func providerOptions(allowInsecureURLs bool) []oauth.ProviderOption {
	if !allowInsecureURLs {
		return nil
	}

	return []oauth.ProviderOption{oauth.WithInsecureURLs(), oauth.WithHTTPClient(providerHTTPClient)}
}

func newGoogleProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	options := providerOptions(allowInsecureURLs)
	options = append(options, oauth.WithOIDC(oauth.OIDCConfig{Issuer: providers.GoogleIssuer, JWKSURL: providers.GoogleJWKSURL, AllowInsecureURLs: allowInsecureURLs, HTTPClient: providerHTTPClient}))
	return providers.Google(config.ClientID, config.ClientSecret, options...), nil
}

func newGitHubProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	return providers.GitHub(config.ClientID, config.ClientSecret, providerOptions(allowInsecureURLs)...), nil
}

func newDiscordProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	return providers.Discord(config.ClientID, config.ClientSecret, providerOptions(allowInsecureURLs)...), nil
}

func newGitLabProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	options := providerOptions(allowInsecureURLs)
	options = append(options, oauth.WithOIDC(oauth.OIDCConfig{Issuer: providers.GitLabIssuer, JWKSURL: providers.GitLabJWKSURL, AllowInsecureURLs: allowInsecureURLs, HTTPClient: providerHTTPClient}))
	return providers.GitLab(config.ClientID, config.ClientSecret, options...), nil
}

func newLinkedInProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	options := providerOptions(allowInsecureURLs)
	options = append(options, oauth.WithOIDC(oauth.OIDCConfig{Issuer: providers.LinkedInIssuer, JWKSURL: providers.LinkedInJWKSURL, AllowInsecureURLs: allowInsecureURLs, HTTPClient: providerHTTPClient}))
	return providers.LinkedIn(config.ClientID, config.ClientSecret, options...), nil
}

func newOIDCProvider(ctx context.Context, config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	options := providerOptions(allowInsecureURLs)
	oidcConfig := oauth.OIDCConfig{Issuer: strings.TrimRight(config.Issuer, "/"), AllowInsecureURLs: allowInsecureURLs}
	if allowInsecureURLs {
		oidcConfig.HTTPClient = providerHTTPClient
	}
	options = append(options, oauth.WithOIDC(oidcConfig))
	discoveryOptions := []providers.OIDCOption{providers.WithProviderName(config.ID)}
	if allowInsecureURLs {
		discoveryOptions = append(discoveryOptions, providers.WithDiscoveryHTTPClient(providerHTTPClient), providers.WithInsecureDiscoveryURLs())
	}
	return providers.OIDC(ctx, config.Issuer, config.ClientID, config.ClientSecret, options, discoveryOptions...), nil
}

func newCustomProvider(config Provider, allowInsecureURLs bool) (*oauth.Provider, error) {
	return oauth.New(config.ID, config.ClientID, config.ClientSecret, config.AuthorizationURL, config.TokenURL, config.Scopes, genericUserInfo(config.UserInfoURL), providerOptions(allowInsecureURLs)...), nil
}

func genericUserInfo(endpoint string) oauth.FetchUserFunc {
	return func(ctx context.Context, client *http.Client, accessToken string) (*oauth.UserInfo, error) {
		var raw struct {
			Subject       string `json:"sub"`
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}

		if err := oauth.GetJSON(ctx, client, endpoint, accessToken, &raw); err != nil {
			return nil, err
		}

		if raw.Subject == "" {
			raw.Subject = raw.ID
		}

		if raw.Subject == "" {
			return nil, fmt.Errorf("provider returned no subject")
		}

		return &oauth.UserInfo{ProviderID: raw.Subject, Email: raw.Email, EmailVerified: raw.EmailVerified, Name: raw.Name}, nil
	}
}

func evaluateOAuthEmail(info *oauth.UserInfo) (string, error) {
	if info == nil || strings.TrimSpace(info.ProviderID) == "" {
		return "", fmt.Errorf("provider returned no subject")
	}

	if len([]byte(strings.TrimSpace(info.ProviderID))) > 512 {
		return "", fmt.Errorf("provider subject is too long")
	}

	email := strings.TrimSpace(info.Email)
	if email == "" || len([]byte(email)) > 320 || !info.EmailVerified {
		return "", fmt.Errorf("provider email is not verified")
	}

	if len([]byte(strings.TrimSpace(info.Name))) > 256 {
		return "", fmt.Errorf("provider name is too long")
	}

	return strings.ToLower(email), nil
}
