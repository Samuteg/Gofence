package recon

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type DNSResult struct {
	Subdomain string
	IP        string
}

type Resolver struct {
	Concurrency int
	client      *dns.Client
}

func NewResolver(concurrency int) *Resolver {
	if concurrency <= 0 {
		concurrency = 100
	}
	return &Resolver{
		Concurrency: concurrency,
		client:      &dns.Client{Timeout: 5 * time.Second},
	}
}

func (r *Resolver) BruteForce(domain, wordlistPath string) ([]DNSResult, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer file.Close()

	// Wildcard detection: a random subdomain resolving to a stable IP means the
	// zone has a catch-all. Every guessed name would then "resolve", producing
	// 100% false positives against providers like Vercel.
	wildcardIP := r.detectWildcard(domain)
	if wildcardIP != "" {
		fmt.Fprintf(os.Stderr, "WARN: wildcard DNS detected (catch-all -> %s); responses matching it will be discarded\n", wildcardIP)
	}

	sem := make(chan struct{}, r.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []DNSResult
	var found int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word == "" {
			continue
		}
		sub := fmt.Sprintf("%s.%s", word, domain)
		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ip := r.resolveA(sub); ip != "" {
				if ip == wildcardIP {
					return
				}
				atomic.AddInt64(&found, 1)
				mu.Lock()
				results = append(results, DNSResult{Subdomain: sub, IP: ip})
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return results, nil
}

func (r *Resolver) detectWildcard(domain string) string {
	rnd := fmt.Sprintf("rnd-%d.%s", time.Now().UnixNano(), domain)
	return r.resolveA(rnd)
}

func (r *Resolver) resolveA(name string) string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := r.client.Exchange(msg, "8.8.8.8:53")
	if err != nil || resp == nil {
		return ""
	}
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func (r *Resolver) AXFR(domain, nameserver string) ([]string, error) {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(domain)

	env, err := t.In(m, nameserver+":53")
	if err != nil {
		return nil, fmt.Errorf("axfr setup: %w", err)
	}

	var records []string
	for e := range env {
		if e.Error != nil {
			return records, e.Error
		}
		for _, rr := range e.RR {
			records = append(records, rr.String())
		}
	}
	return records, nil
}
