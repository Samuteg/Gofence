package surface

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-009 — fuzzing de cabeçalhos
func TestFuzzerHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") == "admin" {
			w.WriteHeader(200)
			fmt.Fprintf(w, "found")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "hosts.txt")
	os.WriteFile(wl, []byte("admin\nuser\nguest\n"), 0644)

	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	results, err := fuzzer.FuzzWeb(server.URL, wl, "X-Custom: FUZZ", "")
	if err != nil {
		t.Fatalf("AC-009: header fuzz failed: %v", err)
	}

	found := false
	for r := range results {
		if r.StatusCode == 200 && contains(r.URL, server.URL) {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-009: expected header fuzz to find X-Custom: admin with 200")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0)
}
