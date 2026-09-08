package recon

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// @spec:AC-046 — alvo em CIDR é expandido e cada host é varrido
func TestScanCIDRExpandsHosts(t *testing.T) {
	// Abre um listener em 127.0.0.1 numa porta efêmera.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AC-046: listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// 127.0.0.1/31 tem dois hosts: 127.0.0.0 e 127.0.0.1. O listener vive em
	// 127.0.0.1; 127.0.0.0 deve sair fechado (sem porta) ou simplesmente não
	// constar — o importante é que o resultado traga o Host 127.0.0.1.
	hosts, err := ExpandCIDR("127.0.0.1/31")
	if err != nil {
		t.Fatalf("AC-046: expand: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("AC-046: expected 2 hosts from /31, got %d", len(hosts))
	}

	scanner := NewPortScanner(5, 0)
	results := scanner.ScanTCPHosts(hosts, []int{port})

	found := false
	for _, r := range results {
		if r.Port == port && r.Host == "127.0.0.1" && r.State == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-046: expected open result for host 127.0.0.1 port %d, got %+v", port, results)
	}
}

// @spec:AC-049 — resultado por host individual
func TestScanCIDRPerHostResults(t *testing.T) {
	hosts, err := ExpandCIDR("127.0.0.1/30") // 4 hosts: 127.0.0.0..3
	if err != nil {
		t.Fatalf("AC-049: expand: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("AC-049: expected 4 hosts from /30, got %d", len(hosts))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AC-049: listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner := NewPortScanner(5, 0)
	results := scanner.ScanTCPHosts(hosts, []int{port})

	// Só 127.0.0.1 tem o listener; os outros hosts da faixa não podem estar
	// marcados como open na mesma porta.
	for _, r := range results {
		if r.State == "open" && r.Host != "127.0.0.1" {
			t.Errorf("AC-049: host %s reported open on %d but only 127.0.0.1 listens", r.Host, r.Port)
		}
	}
}

// @spec:AC-050 — banner identificado vira serviço+versão no resultado
func TestIdentifyServiceFromBanner(t *testing.T) {
	svc, ver := IdentifyService(22, "SSH-2.0-OpenSSH_8.9p1\r\n")
	if svc != "ssh" {
		t.Errorf("AC-050: expected service ssh, got %q", svc)
	}
	if ver != "8.9p1" {
		t.Errorf("AC-050: expected version 8.9p1, got %q", ver)
	}
}

// @spec:AC-051 — serviço sem banner cai no mapa estático como fallback
func TestIdentifyServiceFallbackStaticMap(t *testing.T) {
	svc, ver := IdentifyService(3306, "")
	if svc != "mysql" {
		t.Errorf("AC-051: expected fallback mysql, got %q", svc)
	}
	if ver != "" {
		t.Errorf("AC-051: expected empty version on fallback, got %q", ver)
	}
}

// @spec:AC-056 — retry em timeout antes de marcar fechada
func TestRetryBeforeClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AC-056: listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner := NewPortScanner(5, 50*time.Millisecond)
	scanner.Retries = 3
	calls := 0
	scanner.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("simulated transient drop (attempt %d)", calls)
		}
		return net.DialTimeout(network, addr, timeout)
	}

	results := scanner.ScanTCP("127.0.0.1", []int{port})
	if len(results) != 1 || results[0].State != "open" {
		t.Fatalf("AC-056: expected open after retries, got %+v (dial calls=%d)", results, calls)
	}
	if calls < 3 {
		t.Errorf("AC-056: expected at least 3 dial attempts before success, got %d", calls)
	}
}

// @spec:AC-054 — hosts vivos da faixa são listados
func TestPingSweepListsLiveHosts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AC-054: listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner := NewPortScanner(5, time.Second)
	// 127.0.0.1 tem listener na porta dada; 127.0.0.2 não escuta nada.
	alive := scanner.PingSweep([]string{"127.0.0.1", "127.0.0.2"}, []int{port})

	found := false
	for _, h := range alive {
		if h == "127.0.0.1" {
			found = true
		}
		if h == "127.0.0.2" {
			t.Errorf("AC-054: host 127.0.0.2 reported alive but nothing listens there")
		}
	}
	if !found {
		t.Errorf("AC-054: expected 127.0.0.1 alive, got %v", alive)
	}
}

// @spec:AC-057 — alvo IPv6 literal é varrido sem erro
func TestScanIPv6Literal(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("AC-057: IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner := NewPortScanner(5, 0)
	results := scanner.ScanTCP("::1", []int{port})

	found := false
	for _, r := range results {
		if r.Port == port && r.State == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-057: expected ::1 port %d open, got %+v", port, results)
	}
}