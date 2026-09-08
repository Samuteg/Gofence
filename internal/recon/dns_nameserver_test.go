package recon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// startFakeDNS sobe um servidor DNS na porta efêmera que resolve
// <sub>.demo.local -> 127.0.0.1 (exceto rnd-*, que não resolve = sem wildcard).
func startFakeDNS(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	pc := ln.(*net.UDPConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 {
				q := req.Question[0]
				name := strings.TrimSuffix(q.Name, ".")
				if strings.HasSuffix(name, ".demo.local") && !strings.HasPrefix(name, "rnd-") {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("127.0.0.1"),
					})
				}
			}
			packed, _ := resp.Pack()
			pc.WriteTo(packed, addr)
		}
	}()

	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr().String()
}

// @spec:AC-001 — brute-force de subdomínios usa o nameserver configurado
func TestBruteForceUsesCustomNameserver(t *testing.T) {
	ns := startFakeDNS(t)

	dir := t.TempDir()
	wl := filepath.Join(dir, "subs.txt")
	os.WriteFile(wl, []byte("www\napi\nmail\n"), 0644)

	resolver := NewResolver(5)
	resolver.Nameserver = ns
	results, err := resolver.BruteForce("demo.local", wl)
	if err != nil {
		t.Fatalf("AC-001: brute: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("AC-001: expected 3 subdomains resolved via custom NS, got %d: %+v", len(results), results)
	}
	for _, r := range results {
		if r.IP != "127.0.0.1" {
			t.Errorf("AC-001: expected 127.0.0.1, got %s for %s", r.IP, r.Subdomain)
		}
		if !strings.Contains(r.Subdomain, ".demo.local") {
			t.Errorf("AC-001: unexpected subdomain %q", r.Subdomain)
		}
	}
}

// @spec:AC-001 — sem nameserver configurado, default é 8.8.8.8:53
func TestResolverDefaultNameserver(t *testing.T) {
	r := NewResolver(10)
	if r.Nameserver != "8.8.8.8:53" {
		t.Errorf("AC-001: expected default nameserver 8.8.8.8:53, got %q", r.Nameserver)
	}
}

var _ = fmt.Sprintf