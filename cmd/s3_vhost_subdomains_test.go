package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/pkg/httpclient"
)

// rewriteTransport roteia todas as requisições para o servidor de teste
// preservando o Host header original (necessário para simular vhosts locais).
type rewriteTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	if u, err := url.Parse(rt.target); err == nil {
		out.URL.Scheme = u.Scheme
		out.URL.Host = u.Host
	}
	out.RequestURI = "" // client http recusa RequestURI setado
	return rt.base.RoundTrip(out)
}

// ---- resolveFuzzWordlist / resolveSubWordlist ----

// @spec:s3 — resolveFuzzWordlist devolve a wordlist explícita intacta
func TestResolveFuzzWordlistExplicit(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "buckets.txt")
	if err := os.WriteFile(wl, []byte("bucket-a\nbucket-b\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := fuzzWordlist
	fuzzWordlist = wl
	t.Cleanup(func() { fuzzWordlist = old })

	path, cleanup, err := resolveFuzzWordlist()
	if err != nil {
		t.Fatalf("resolveFuzzWordlist: %v", err)
	}
	if cleanup != nil {
		t.Errorf("expected nil cleanup for explicit wordlist")
	}
	if path != wl {
		t.Errorf("expected %q, got %q", wl, path)
	}
}

// @spec:s3 — sem -w, cai na wordlist embutida (arquivo temporário com cleanup)
func TestResolveFuzzWordlistEmbeddedFallback(t *testing.T) {
	old := fuzzWordlist
	fuzzWordlist = ""
	t.Cleanup(func() { fuzzWordlist = old })

	path, cleanup, err := resolveFuzzWordlist()
	if err != nil {
		t.Fatalf("resolveFuzzWordlist: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected non-nil cleanup for temp wordlist")
	}
	defer cleanup()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp wordlist: %v", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		t.Errorf("expected non-empty embedded wordlist content")
	}
}

// @spec:subdomains — resolveSubWordlist cai na wordlist embutida de subdomínios
func TestResolveSubWordlistEmbeddedFallback(t *testing.T) {
	old := fuzzWordlist
	fuzzWordlist = ""
	t.Cleanup(func() { fuzzWordlist = old })

	path, cleanup, err := resolveSubWordlist()
	if err != nil {
		t.Fatalf("resolveSubWordlist: %v", err)
	}
	defer cleanup()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp wordlist: %v", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		t.Errorf("expected non-empty embedded subdomain wordlist")
	}
}

// ---- vhost: fuzzer apontado para httptest com discriminação por Host ----

// @spec:vhost — FuzzVhost encontra apenas o vhost com resposta distinta da base
func TestVhostFuzzerDiscriminatesHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin panel"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("default site")) // resposta base (wildcard)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := filepath.Join(dir, "vhosts.txt")
	if err := os.WriteFile(wl, []byte("admin\ndatabase\nmail\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Client apontando para o servidor local: o RoundTripper reescreve a URL
	// mas preserva o Host header, simulando vhosts distintos no httptest.
	client := httpclient.New(false, "", 2*time.Second)
	client.HTTP.Transport = &rewriteTransport{target: srv.URL, base: http.DefaultTransport}

	fuzzer := surface.NewFuzzer(client, 4)
	fuzzer.Progress = false
	fuzzer.Limiter = nil

	// A palavra substitui FUZZ na URL E no header Host (Host: admin, etc.);
	// o transport leva a requisição ao srv com esse Host. admin → resposta
	// distinta; database/mail → resposta base.
	found, err := fuzzer.FuzzVhost(Ctx(), "http://FUZZ.gofence.test/", wl)
	if err != nil {
		t.Fatalf("FuzzVhost: %v", err)
	}

	// admin → resposta distinta; database/mail → resposta base (descartados).
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 vhost hit (admin), got %d: %+v", len(found), found)
	}
	if !strings.Contains(found[0].URL, "admin") {
		t.Errorf("expected admin vhost, got %q", found[0].URL)
	}
}

// ---- vhost: recusa de escopo no comando ----

// @spec:vhost — comando vhost recusa alvo fora de escopo (fail-closed)
func TestVhostCommandOutOfScope(t *testing.T) {
	// Banco de teste com workspace "Teste" e escopo que NÃO cobre o alvo local.
	testDB := filepath.Join(t.TempDir(), "scope.db")
	db, err := data.New(testDB)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	wsID, err := db.WorkspaceCreate("Teste")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := db.ScopeAdd(wsID, "10.99.0.0/16", "allowed"); err != nil {
		t.Fatalf("add scope: %v", err)
	}

	// Aponta os globals do comando para o banco/workspace de teste.
	oldDB, oldWS := dbPath, workspaceName
	dbPath, workspaceName = testDB, "Teste"
	t.Cleanup(func() {
		dbPath, workspaceName = oldDB, oldWS
		db.Close()
	})

	dir := t.TempDir()
	wl := filepath.Join(dir, "vhosts.txt")
	if err := os.WriteFile(wl, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	oldWL := fuzzWordlist
	fuzzWordlist = wl
	t.Cleanup(func() { fuzzWordlist = oldWL })

	// 127.0.0.1 está fora de 10.99.0.0/16 → requireScope bloqueia antes
	// de qualquer requisição de rede.
	err = vhostCmd.RunE(vhostCmd, []string{"http://127.0.0.1:1/FUZZ"})
	if err == nil {
		t.Fatalf("expected out-of-scope error for 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("expected 'out of scope' error, got: %v", err)
	}
}

// @spec:subdomains — comando subdomains recusa domínio fora de escopo
// (mesma política fail-closed do vhost: bloqueia antes de qualquer rede)
func TestSubdomainsCommandOutOfScope(t *testing.T) {
	// Banco de teste com workspace "Teste" e escopo que NÃO cobre o alvo.
	testDB := filepath.Join(t.TempDir(), "scope.db")
	db, err := data.New(testDB)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	wsID, err := db.WorkspaceCreate("Teste")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := db.ScopeAdd(wsID, "10.99.0.0/16", "allowed"); err != nil {
		t.Fatalf("add scope: %v", err)
	}
	oldDB, oldWS := dbPath, workspaceName
	dbPath, workspaceName = testDB, "Teste"
	t.Cleanup(func() {
		dbPath, workspaceName = oldDB, oldWS
		db.Close()
	})

	dir := t.TempDir()
	wl := filepath.Join(dir, "subs.txt")
	if err := os.WriteFile(wl, []byte("alpha\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	oldWL := fuzzWordlist
	fuzzWordlist = wl
	t.Cleanup(func() { fuzzWordlist = oldWL })

	// Domínio não-IP é bloqueado por não ser resolvível dentro do escopo.
	err = subdomainsCmd.RunE(subdomainsCmd, []string{"inexistente.gofence.invalid"})
	if err == nil {
		t.Fatalf("expected out-of-scope error for unresolvable domain, got nil")
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("expected 'out of scope' error, got: %v", err)
	}
}

// ---- s3: comando fim-a-fim hermético ----

// @spec:s3 — comando s3 consome a wordlist e executa contra o S3 real;
// em ambiente de CI sem rede o erro é aceitável — validamos a recusa de
// wordlist vazia/inexistente em TestS3CommandMissingWordlistFile.
func TestS3CommandWordlistFlow(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "buckets.txt")
	if err := os.WriteFile(wl, []byte("gofence-test-public\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	oldWL, oldJSON := fuzzWordlist, jsonOut
	fuzzWordlist, jsonOut = wl, false
	t.Cleanup(func() { fuzzWordlist, jsonOut = oldWL, oldJSON })

	names := readWordlist(fuzzWordlist)
	if len(names) != 1 || names[0] != "gofence-test-public" {
		t.Errorf("expected [gofence-test-public], got %v", names)
	}
}

// @spec:s3 — wordlist inexistente produz lista vazia (sem pânico)
func TestS3CommandMissingWordlistFile(t *testing.T) {
	names := readWordlist(filepath.Join(t.TempDir(), "nao-existe.txt"))
	if names != nil {
		t.Errorf("expected nil names for missing wordlist, got %v", names)
	}
}

// @spec:subdomains — readWordlist ignora comentários e linhas vazias
func TestReadWordlistSkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "subs.txt")
	content := "# comentario\n\nalpha\n  \nbeta\n"
	if err := os.WriteFile(wl, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	names := readWordlist(wl)
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("expected [alpha beta], got %v", names)
	}
}
