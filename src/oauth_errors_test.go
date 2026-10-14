package main

import "testing"

func TestOAuthCallbackErrorMessageUsesTrustedDescription(t *testing.T) {
	if got := oauthCallbackErrorMessage("access_denied", "The user denied the request.", "fallback"); got != "The user denied the request." {
		t.Fatalf("trusted description = %q", got)
	}
}

func TestOAuthCallbackErrorMessageDoesNotReflectUnknownDescription(t *testing.T) {
	const fallback = "The identity-provider login was not approved."

	if got := oauthCallbackErrorMessage("access_denied", "secret", fallback); got != fallback {
		t.Fatalf("unknown description = %q", got)
	}
}

func TestOAuthCallbackErrorMessageUsesSafeCodeFallback(t *testing.T) {
	if got := oauthCallbackErrorMessage("temporarily_unavailable", "secret", "fallback"); got != "The identity provider is temporarily unavailable." {
		t.Fatalf("temporary failure = %q", got)
	}
}
