package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
)

type bufferWriteCloser struct {
	*bytes.Buffer
}

func (bufferWriteCloser) Close() error {
	return nil
}

func qrPNG(value string) ([]byte, error) {
	code, err := qrcode.New(value)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	writer := standard.NewWithWriter(
		bufferWriteCloser{Buffer: &output},
		standard.WithBuiltinImageEncoder(standard.PNG_FORMAT),
	)

	if err := code.Save(writer); err != nil {
		return nil, err
	}

	if output.Len() == 0 {
		return nil, errors.New("qr writer produced no output")
	}

	return append([]byte(nil), output.Bytes()...), nil
}

func (s *Store) qrHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		id := strings.TrimPrefix(r.URL.Path, "/api/qr/")
		login, ok := s.loginSnapshot(id)
		if !ok {
			http.NotFound(w, r)
			return
		}

		if !time.Now().Before(login.Expires) {
			s.expireLogin(id, time.Now())
			errOut(w, http.StatusGone, "Login has expired.")
			return
		}

		image, err := qrPNG(loginQRValue(cfg.Issuer, id))
		if err != nil {
			http.Error(w, "could not render QR", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(image)
	}
}

func relayQRHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			errOut(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}

		image, err := qrPNG(relayQRValue(cfg.Issuer))
		if err != nil {
			http.Error(w, "could not render QR", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(image)
	}
}

func relayQRValue(issuer string) string {
	return "relayid://relay?origin=" + url.QueryEscape(issuer)
}

func loginQRValue(issuer, id string) string {
	return "relayid://login?origin=" + url.QueryEscape(issuer) + "&id=" + url.QueryEscape(id)
}
