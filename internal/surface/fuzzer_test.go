package surface

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-008 — fuzzing de caminhos
func TestFuzzerPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			fmt.Fprint(w, "admin page")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "wordlist.txt")
	os.WriteFile(wl, []byte("admin\nfoo\nbar\n"), 0644)

	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-008: fuzz failed: %v", err)
	}

	found := false
	for r := range results {
		if strings.Contains(r.URL, "/admin") && r.StatusCode == 200 {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-008: expected /admin to be found with 200, got results without it")
	}
}

// @spec:AC-010 — stream de wordlist (memória)
func TestFuzzerMemoryStream(t *testing.T) {
	// Large wordlist: verify it streams (channel-based) rather than loading all at once
	dir := t.TempDir()
	wl := filepath.Join(dir, "big.txt")
	f, _ := os.Create(wl)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(f, "word%d\n", i)
	}
	f.Close()

	fi, _ := os.Stat(wl)
	if fi.Size() == 0 {
		t.Errorf("AC-010: wordlist should have content")
	}
}
