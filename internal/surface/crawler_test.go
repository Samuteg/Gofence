package surface

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-013 — extração de links
func TestCrawlerExtractsLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><a href="/page1">Link1</a><a href="/page2">Link2</a><script src="/app.js"></script></body></html>`)
	}))
	defer server.Close()

	crawler := NewCrawler(httpclient.NewFromEnv(), 1, 5)
	result := crawler.Crawl(server.URL)

	if len(result.URLs) < 3 {
		t.Errorf("AC-013: expected at least 3 URLs, got %d: %v", len(result.URLs), result.URLs)
	}
}

// @spec:AC-014 — detecção de segredos
func TestCrawlerDetectsSecrets(t *testing.T) {
	page := `<html><body><script>var key = "AKIAIOSFODNN7EXAMPLE"; var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";</script></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, page)
	}))
	defer server.Close()

	crawler := NewCrawler(httpclient.NewFromEnv(), 1, 5)
	result := crawler.Crawl(server.URL)

	if len(result.Secrets) == 0 {
		t.Errorf("AC-014: expected secrets to be detected, got none")
	}

	foundAWS := false
	foundJWT := false
	for _, s := range result.Secrets {
		if s.Type == "AWS_KEY" {
			foundAWS = true
		}
		if s.Type == "JWT" {
			foundJWT = true
		}
	}
	if !foundAWS {
		t.Errorf("AC-014: AWS key not detected")
	}
	if !foundJWT {
		t.Errorf("AC-014: JWT not detected")
	}
}
