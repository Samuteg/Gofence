package surface

import (
	"context"
	"fmt"

	"github.com/nixteg/gofence/internal/recon"
)

// DNSFuzzResult é um subdomínio que resolveu no modo --dns do fuzzer.
type DNSFuzzResult struct {
	Subdomain string `json:"subdomain"`
	IP        string `json:"ip"`
}

// FuzzDNS resolve cada palavra como subdomínio de `domain`, usando o
// Resolver do recon (com o nameserver configurado). Retorna os que resolvem.
func FuzzDNS(concurrency int, domain, wordlistPath, nameserver string) ([]DNSFuzzResult, error) {
	return FuzzDNSContext(context.Background(), concurrency, domain, wordlistPath, nameserver)
}

// FuzzDNSContext é o FuzzDNS com cancelamento (Ctrl+C).
func FuzzDNSContext(ctx context.Context, concurrency int, domain, wordlistPath, nameserver string) ([]DNSFuzzResult, error) {
	resolver := recon.NewResolver(concurrency)
	if nameserver != "" {
		resolver.Nameserver = nameserver
	}
	results, err := resolver.BruteForceContext(ctx, domain, wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("dns fuzz: %w", err)
	}
	out := make([]DNSFuzzResult, 0, len(results))
	for _, r := range results {
		out = append(out, DNSFuzzResult{Subdomain: r.Subdomain, IP: r.IP})
	}
	return out, nil
}