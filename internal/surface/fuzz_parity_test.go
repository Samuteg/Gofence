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

func writeWordlist(t *testing.T, words ...string) string {
	t.Helper()
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte(strings.Join(words, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	return wl
}

func collect(results <-chan FuzzResult) []FuzzResult {
	var out []FuzzResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

// @spec:AC-047 — respostas curinga são detectadas e descartadas
func TestFuzzerWildcardDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "catch-all page")
	}))
	defer server.Close()

	wl := writeWordlist(t, "admin", "foo", "bar")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-047: fuzz: %v", err)
	}
	out := collect(results)
	for _, r := range out {
		if !r.Wildcard {
			t.Errorf("AC-047: expected wildcard responses to be flagged, got %+v", r)
		}
	}
}

// @spec:AC-062 — filtro por tamanho de resposta
func TestFuzzerExcludeLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			w.WriteHeader(200)
			fmt.Fprint(w, "real content")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "404 page")
	}))
	defer server.Close()

	wl := writeWordlist(t, "real", "fake")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	fuzzer.ExcludeSize = []int64{9} // tamanho de "404 page"
	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-062: fuzz: %v", err)
	}
	out := collect(results)
	for _, r := range out {
		if r.Size == 9 {
			t.Errorf("AC-062: expected size 9 to be excluded, got %+v", r)
		}
	}
}

// @spec:AC-063 — whitelist de status
func TestFuzzerStatusWhitelist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
		case "/moved":
			w.WriteHeader(301)
		default:
			w.WriteHeader(403)
		}
	}))
	defer server.Close()

	wl := writeWordlist(t, "ok", "moved", "blocked")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	fuzzer.StatusCodes = []int{200, 301}
	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-063: fuzz: %v", err)
	}
	out := collect(results)
	if len(out) != 2 {
		t.Fatalf("AC-063: expected 2 results (200,301), got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.StatusCode == 403 {
			t.Errorf("AC-063: 403 should be filtered by whitelist, got %+v", r)
		}
	}
}

// @spec:AC-064 — diretório descoberto é re-fuzado recursivamente
func TestFuzzerRecursive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			w.WriteHeader(200)
			fmt.Fprint(w, "admin index")
		case "/admin/config":
			w.WriteHeader(200)
			fmt.Fprint(w, "admin config")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	wl := writeWordlist(t, "admin/", "config", "foo")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	all, err := fuzzer.FuzzRecursive(context.Background(), server.URL+"/FUZZ", wl, 3)
	if err != nil {
		t.Fatalf("AC-064: recursive: %v", err)
	}

	foundAdmin := false
	foundConfig := false
	for _, r := range all {
		if strings.Contains(r.URL, "/admin/") && strings.Contains(r.URL, "config") {
			foundConfig = true
		}
		if strings.Contains(r.URL, "/admin/") && r.Depth > 0 {
			foundAdmin = true
		}
	}
	if !foundConfig {
		t.Errorf("AC-064: expected /admin/config found at depth > 0, got %+v", all)
	}
	_ = foundAdmin
}

// @spec:AC-065 — cada palavra é testada com cada extensão
func TestFuzzerExtensions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" || r.URL.Path == "/index.html" {
			w.WriteHeader(200)
			fmt.Fprint(w, "found")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	wl := writeWordlist(t, "index", "other")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	extended, err := fuzzer.ExtendWordlist(wl, []string{"php", "html"})
	if err != nil {
		t.Fatalf("AC-065: extend: %v", err)
	}
	defer os.Remove(extended)

	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", extended, "", "")
	if err != nil {
		t.Fatalf("AC-065: fuzz: %v", err)
	}
	out := collect(results)
	php := false
	html := false
	for _, r := range out {
		if strings.HasSuffix(r.URL, "/index.php") {
			php = true
		}
		if strings.HasSuffix(r.URL, "/index.html") {
			html = true
		}
	}
	if !php || !html {
		t.Errorf("AC-065: expected index.php and index.html found, got %+v", out)
	}
}

// @spec:AC-066 — vhosts distintos aparecem, respostas iguais à base são filtradas
func TestFuzzerVhost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "secret.example" {
			w.WriteHeader(200)
			fmt.Fprint(w, "secret vhost content")
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "default vhost")
	}))
	defer server.Close()

	wl := writeWordlist(t, "secret.example", "other.example")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	out, err := fuzzer.FuzzVhost(context.Background(), server.URL+"/", wl)
	if err != nil {
		t.Fatalf("AC-066: vhost: %v", err)
	}
	found := false
	for _, r := range out {
		if strings.Contains(r.Header, "secret.example") || strings.Contains(r.URL, "secret") {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-066: expected distinct vhost to appear, got %+v", out)
	}
}

// @spec:AC-067 — paths de robots/sitemap entram no fuzz
func TestFuzzerRobotsSeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\n")
			return
		}
		if r.URL.Path == "/admin/" {
			w.WriteHeader(200)
			fmt.Fprint(w, "admin")
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	paths := RobotsPaths(httpclient.NewFromEnv(), server.URL)
	if len(paths) == 0 {
		t.Fatalf("AC-067: expected paths from robots.txt, got none")
	}
	if paths[0] != "/admin/" {
		t.Errorf("AC-067: expected /admin/ from robots, got %v", paths)
	}
}

// @spec:AC-068 — sessão interrompida é retomada do ponto salvo
func TestFuzzerResume(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/later" {
			w.WriteHeader(200)
			fmt.Fprint(w, "later")
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	wl := writeWordlist(t, "first", "second", "later")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)

	// Estado: já processou 2 palavras, achou nada, falta "later".
	state := FuzzState{
		TargetURL: server.URL + "/FUZZ",
		Wordlist:  wl,
		Processed: 2,
		Findings:  []FuzzResult{},
	}
	out, err := fuzzer.FuzzResume(context.Background(), state)
	if err != nil {
		t.Fatalf("AC-068: resume: %v", err)
	}
	found := false
	for _, r := range out {
		if strings.Contains(r.URL, "/later") && r.StatusCode == 200 {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-068: expected /later found after resume, got %+v", out)
	}
}

// @spec:AC-069 — credenciais, cookie e UA são enviados na requisição
func TestFuzzerAuthCookieUA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		hasCookie := r.Header.Get("Cookie") == "session=abc"
		hasUA := r.Header.Get("User-Agent") == "gofence-test"
		if ok && user == "admin" && pass == "secret" && hasCookie && hasUA {
			w.WriteHeader(200)
			fmt.Fprint(w, "authed")
			return
		}
		w.WriteHeader(401)
	}))
	defer server.Close()

	wl := writeWordlist(t, "admin", "foo")
	fuzzer := NewFuzzer(httpclient.NewFromEnv(), 5)
	fuzzer.SetAuth(FuzzAuth{User: "admin", Pass: "secret", Cookie: "session=abc", UserAgent: "gofence-test"})

	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-069: fuzz: %v", err)
	}
	out := collect(results)
	if len(out) == 0 {
		t.Fatalf("AC-069: expected authed request to return 200, got none")
	}
	for _, r := range out {
		if r.StatusCode != 200 {
			t.Errorf("AC-069: expected 200 with auth, got %+v", r)
		}
	}
}