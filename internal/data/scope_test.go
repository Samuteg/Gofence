package data

import (
	"net"
	"path/filepath"
	"testing"
)

// @spec:AC-026 — bloqueio de IP fora do escopo
func TestScopeGuardBlocksOutOfScope(t *testing.T) {
	guard := NewScopeGuard([]string{"10.0.0.0/8"})
	ip := net.ParseIP("192.168.1.1")
	if guard.IsAllowed(ip) {
		t.Errorf("AC-026: IP 192.168.1.1 should be blocked, but was allowed")
	}
	if guard.CheckAndLog(ip, "dns") {
		t.Errorf("AC-026: CheckAndLog should return false for out-of-scope IP")
	}
}

// @spec:AC-027 — liberação de IP dentro do escopo
func TestScopeGuardAllowsInScope(t *testing.T) {
	guard := NewScopeGuard([]string{"10.0.0.0/8"})
	ip := net.ParseIP("10.0.1.5")
	if !guard.IsAllowed(ip) {
		t.Errorf("AC-027: IP 10.0.1.5 should be allowed, but was blocked")
	}
	if !guard.CheckAndLog(ip, "dns") {
		t.Errorf("AC-027: CheckAndLog should return true for in-scope IP")
	}
}

// @spec:AC-035 — alvo fora do escopo é bloqueado (IP, ip:porta, URL, irreconhecível)
func TestCheckHostBlocksOutOfScope(t *testing.T) {
	guard := NewScopeGuard([]string{"10.0.0.0/8"})
	for _, host := range []string{"192.168.1.1", "192.168.1.1:443", "https://192.168.1.1/x", "nope.invalid", ""} {
		if CheckHost(guard, host, "test") {
			t.Errorf("AC-035: host %q should be blocked, but was allowed", host)
		}
	}
}

// @spec:AC-036 — alvo dentro do escopo passa (IP, ip:porta, URL)
func TestCheckHostAllowsInScope(t *testing.T) {
	guard := NewScopeGuard([]string{"10.0.0.0/8"})
	for _, host := range []string{"10.0.1.5", "10.0.1.5:8443", "https://10.0.1.5/x"} {
		if !CheckHost(guard, host, "test") {
			t.Errorf("AC-036: host %q should be allowed, but was blocked", host)
		}
	}
}

// @spec:AC-038 — guarda de escopo vazio bloqueia tudo
func TestEmptyScopeBlocksAll(t *testing.T) {
	guard := NewScopeGuard(nil)
	for _, host := range []string{"10.0.1.5", "8.8.8.8"} {
		if CheckHost(guard, host, "test") {
			t.Errorf("AC-038: host %q should be blocked by empty scope, but was allowed", host)
		}
	}
}

// @spec:AC-036 — guarda carregada do workspace libera o contratado
func TestGuardForWorkspaceLoadsCIDRs(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("AC-036: failed to open db: %v", err)
	}
	defer db.Close()
	wsID, err := db.WorkspaceCreate("Escopo")
	if err != nil {
		t.Fatalf("AC-036: failed to create workspace: %v", err)
	}
	if err := db.ScopeAdd(wsID, "10.0.0.0/8", "allowed"); err != nil {
		t.Fatalf("AC-036: failed to add scope: %v", err)
	}
	guard, err := GuardForWorkspace(db, wsID)
	if err != nil {
		t.Fatalf("AC-036: GuardForWorkspace failed: %v", err)
	}
	if !CheckHost(guard, "10.0.1.5", "test") {
		t.Errorf("AC-036: 10.0.1.5 should be allowed by workspace scope")
	}
	if CheckHost(guard, "192.168.1.1", "test") {
		t.Errorf("AC-036: 192.168.1.1 should be blocked by workspace scope")
	}
}

// @spec:AC-039 — filtro mantém só os hosts dentro do escopo
func TestFilterAllowedKeepsInScopeOnly(t *testing.T) {
	guard := NewScopeGuard([]string{"10.0.0.0/8"})
	got := FilterAllowed(guard, []string{"10.0.0.1", "192.168.1.1", "10.0.0.2"}, "dns")
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Errorf("AC-039: expected only in-scope hosts, got %v", got)
	}
}
