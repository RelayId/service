package main

import "testing"

func TestReservedDemoCodeCannotBeGeneratedNormally(t *testing.T) {
	for range 1000 {
		code, err := mobileCode(2)
		if err != nil {
			t.Fatal(err)
		}
		if normalizeMobileCode(code) == normalizeMobileCode(demoMobileCode) {
			t.Fatalf("normal generator produced reserved demo code %q", code)
		}
	}
}
