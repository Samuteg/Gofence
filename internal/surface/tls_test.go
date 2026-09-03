package surface

import (
	"crypto/tls"
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

// @spec:AC-011b — obsolete ciphers are graded C, not reported equal to good ones
func TestCipherGrading(t *testing.T) {
	weak := gradeCipher(tlsCipherByName(t, "TLS_RSA_WITH_RC4_128_SHA"))
	if weak.Grade != "C" || !weak.Weak {
		t.Errorf("AC-011b: RC4 cipher should grade C/weak, got %+v", weak)
	}
	strong := gradeCipher(tlsCipherByName(t, "TLS_AES_128_GCM_SHA256"))
	if strong.Grade != "A" {
		t.Errorf("AC-011b: AES-GCM cipher should grade A, got %+v", strong)
	}
	cbc := gradeCipher(tlsCipherByName(t, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"))
	if cbc.Grade != "B" {
		t.Errorf("AC-011b: CBC cipher should grade B, got %+v", cbc)
	}
}

func tlsCipherByName(t *testing.T, name string) *tls.CipherSuite {
	t.Helper()
	for _, cs := range tls.CipherSuites() {
		if cs.Name == name {
			return cs
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.Name == name {
			return cs
		}
	}
	t.Fatalf("cipher %s not found", name)
	return nil
}
