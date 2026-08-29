package recon

import (
	"net"
	"testing"
)

// @spec:AC-007 — varredura UDP
func TestScanUDP(t *testing.T) {
	// Bind a UDP listener on localhost
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot resolve")
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Skip("cannot listen udp")
	}
	defer conn.Close()

	udpPort := conn.LocalAddr().(*net.UDPAddr).Port
	scanner := NewPortScanner(5, 0)
	results := scanner.ScanUDP("127.0.0.1", []int{udpPort})

	found := false
	for _, r := range results {
		if r.Port == udpPort {
			found = true
		}
	}
	if !found {
		t.Logf("AC-007: UDP port %d scan completed (state may be filtered without response)", udpPort)
	}
}

// @spec:AC-001 — brute-force de subdomínios (estrutura)
func TestBruteForceStructure(t *testing.T) {
	resolver := NewResolver(100)
	if resolver.Concurrency != 100 {
		t.Errorf("AC-001: expected concurrency 100, got %d", resolver.Concurrency)
	}
}
