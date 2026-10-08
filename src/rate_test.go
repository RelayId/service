package main

import (
	"testing"
	"time"
)

func TestRateLimiterWindowSemantics(t *testing.T) {
	book := newRateBook()
	for index := range 10 {
		if !book.allowWindow("authorize", 100*time.Millisecond, 10) {
			t.Fatalf("initial request %d was unexpectedly rejected", index)
		}
	}

	time.Sleep(15 * time.Millisecond)
	if !book.allowWindow("authorize", 100*time.Millisecond, 10) {
		t.Fatal("window limiter did not refill at the configured steady-state rate")
	}
}
