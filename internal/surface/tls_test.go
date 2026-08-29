package surface

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// @spec:AC-011 — inspeção de certificado
func TestAnalyzeTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	// httptest server uses self-signed cert on 127.0.0.1:port
	host := server.Listener.Addr().String()

	info, err := AnalyzeTLS(host, false)
	if err != nil {
		t.Fatalf("AC-011: failed to analyze TLS: %v", err)
	}
	if info.FingerprintSHA256 == "" {
		t.Errorf("AC-011: expected SHA-256 fingerprint, got empty")
	}
	if info.Subject == "" {
		t.Errorf("AC-011: expected subject, got empty")
	}
}
