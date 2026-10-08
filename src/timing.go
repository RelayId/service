package main

import "time"

const (
	oidcAuthorizationCodeLifetime = time.Minute
	oidcTokenLifetime             = 5 * time.Minute
	deviceRequestClockSkew        = 45 * time.Second
	deviceReplayNonceLifetime     = 2 * time.Minute
	upstreamOAuthStateLifetime    = 5 * time.Minute
)
