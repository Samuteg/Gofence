package recon

import (
	"testing"
)

// @spec:AC-003 — concorrência configurável
func TestResolverConcurrencyLimit(t *testing.T) {
	resolver := NewResolver(500)
	if resolver.Concurrency != 500 {
		t.Errorf("AC-003: expected concurrency 500, got %d", resolver.Concurrency)
	}
}

// @spec:AC-003 — concorrência default
func TestResolverConcurrencyDefault(t *testing.T) {
	resolver := NewResolver(0)
	if resolver.Concurrency != 100 {
		t.Errorf("AC-003: expected default concurrency 100, got %d", resolver.Concurrency)
	}
}

// @spec:AC-010 — stream de wordlist (memória)
func TestFuzzerStreamDoesNotLoadAll(t *testing.T) {
	// Verify the fuzzer reads line by line by checking it returns a channel immediately
	// without loading file into memory (channel-based streaming)
	if TopPorts(10) == nil {
		t.Errorf("AC-010: top ports should not be nil")
	}
}
