package main

import "strings"

var trustedOAuthErrorDescriptions = map[string]string{
	"Authorization parameter is too large.":  "Authorization parameter is too large.",
	"Too many authorization attempts.":       "Too many authorization attempts.",
	"Only code response_type is supported.":  "Only code response_type is supported.",
	"Only query response_mode is supported.": "Only query response_mode is supported.",
	"openid scope is required.":              "openid scope is required.",
	"Requested scope is not supported.":      "Requested scope is not supported.",
	"Invalid PKCE request.":                  "Invalid PKCE request.",
	"Relay is temporarily busy.":             "Relay is temporarily busy.",
	"The user denied the request.":           "The user denied the request.",
	"The identity provider denied access.":   "The identity provider denied access.",
}

func trustedOAuthErrorDescription(description string) string {
	description = strings.TrimSpace(description)
	return trustedOAuthErrorDescriptions[description]
}

func oauthCallbackErrorMessage(code, description, fallback string) string {
	if message := trustedOAuthErrorDescription(description); message != "" {
		return message
	}

	switch code {
	case "access_denied":
		return fallback
	case "temporarily_unavailable":
		return "The identity provider is temporarily unavailable."
	case "invalid_request":
		return "The identity-provider request was invalid."
	case "invalid_scope":
		return "The requested identity information is not supported."
	default:
		return fallback
	}
}
