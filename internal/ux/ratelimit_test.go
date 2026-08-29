package ux

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// @spec:AC-032 — perfil Sneaky
func TestRateLimiterSneaky(t *testing.T) {
	limiter := NewLimiter(ProfileSneaky)
	if limiter.Limit() != rate.Limit(1) {
		t.Errorf("AC-032: Sneaky profile should be 1 req/s, got %v", limiter.Limit())
	}
}

// @spec:AC-033 — perfil Normal
func TestRateLimiterNormal(t *testing.T) {
	limiter := NewLimiter(ProfileNormal)
	if limiter.Limit() != rate.Limit(50) {
		t.Errorf("AC-033: Normal profile should be 50 req/s, got %v", limiter.Limit())
	}
}

// @spec:AC-034 — perfil Aggressive
func TestRateLimiterAggressive(t *testing.T) {
	limiter := NewLimiter(ProfileAggressive)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if !limiter.Allow() {
			break
		}
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("AC-034: Aggressive should allow burst quickly, took %v", elapsed)
	}
}
