package httpclient

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nixteg/gofence/internal/config"
)

// @spec:httpclient — New retorna client funcional com proxy configurado
func TestNewWithProxy(t *testing.T) {
	c := New(false, "http://127.0.0.1:8080", 5*time.Second)
	if c.HTTP.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", c.HTTP.Timeout)
	}
	tr := c.HTTP.Transport.(*http.Transport)
	if tr.Proxy == nil {
		t.Fatalf("expected proxy transport func, got nil")
	}
	u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
	if err != nil || u == nil || u.Host != "127.0.0.1:8080" {
		t.Errorf("expected proxy 127.0.0.1:8080, got %v (err %v)", u, err)
	}
}

// @spec:httpclient — TLS skip verificado na configuração do transport
func TestNewTLSSkipVerify(t *testing.T) {
	c := New(true, "", time.Second)
	tr := c.HTTP.Transport.(*http.Transport)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=true")
	}
	c2 := New(false, "", time.Second)
	tr2 := c2.HTTP.Transport.(*http.Transport)
	if tr2.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=false")
	}
}

// @spec:httpclient — resolveTLSSkipVerify: env > config > default seguro
func TestResolveTLSSkipVerify(t *testing.T) {
	t.Run("env true wins", func(t *testing.T) {
		t.Setenv("GOFENCE_TLS_SKIP_VERIFY", "true")
		if !resolveTLSSkipVerify() {
			t.Errorf("expected true from env")
		}
	})
	t.Run("env false wins over config", func(t *testing.T) {
		config.Init()
		t.Setenv("GOFENCE_TLS_SKIP_VERIFY", "false")
		if resolveTLSSkipVerify() {
			t.Errorf("expected false from env")
		}
	})
	t.Run("default is false", func(t *testing.T) {
		config.Init()
		if resolveTLSSkipVerify() {
			t.Errorf("expected secure default false")
		}
	})
}

// @spec:httpclient — proxy: GOFENCE_PROXY_URL > config > HTTP_PROXY
func TestResolveProxy(t *testing.T) {
	t.Run("gofence env wins", func(t *testing.T) {
		t.Setenv("GOFENCE_PROXY_URL", "http://a:1")
		t.Setenv("HTTP_PROXY", "http://b:2")
		if got := resolveProxy(); got != "http://a:1" {
			t.Errorf("expected http://a:1, got %q", got)
		}
	})
	t.Run("falls back to HTTP_PROXY", func(t *testing.T) {
		t.Setenv("GOFENCE_PROXY_URL", "")
		t.Setenv("HTTP_PROXY", "http://b:2")
		if got := resolveProxy(); got != "http://b:2" {
			t.Errorf("expected http://b:2, got %q", got)
		}
	})
}

// @spec:httpclient — client navega em servidor local com verificação TLS
func TestRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	c := New(false, "", 2*time.Second)
	resp, err := c.HTTP.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected 418, got %d", resp.StatusCode)
	}
}
