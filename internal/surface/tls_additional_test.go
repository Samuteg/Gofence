package surface

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// @spec:AC-012 — detecção de TLS downgrade
func TestTLSDowngradeDetection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	host := server.Listener.Addr().String()
	info, err := AnalyzeTLS(host, true)
	if err != nil {
		t.Fatalf("AC-012: failed to analyze TLS: %v", err)
	}
	// httptest uses TLS 1.2+ so no insecure protocols expected,
	// but the function should populate the insecure_protocols list
	if info.Protocols == nil {
		t.Errorf("AC-012: expected protocols list to be populated")
	}
}
