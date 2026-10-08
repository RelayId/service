package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONRejectsNullObject(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/codes", strings.NewReader("null"))
	request.Header.Set("Content-Type", "application/json")

	var input struct{}
	if err := readJSON(request, &input); err == nil {
		t.Fatal("readJSON accepted a JSON null value where an object is required")
	}
}
