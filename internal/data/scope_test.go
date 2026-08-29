package data

import (
	"net"
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
