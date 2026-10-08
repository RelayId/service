// Package web embeds Relay's browser assets and templates.
package web

import (
	"embed"
	"io/fs"
)

// Files contains the service's complete browser UI.
//
//go:embed templates/*.html static
var Files embed.FS

func Favicon() []byte {
	icon, err := Files.ReadFile("static/favicon.ico")
	if err != nil {
		panic(err)
	}

	return icon
}

func StaticFS() (fs.FS, error) {
	return fs.Sub(Files, "static")
}
