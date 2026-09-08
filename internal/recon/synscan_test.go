package recon

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeSynProbe simula um probe que responde SYN-ACK para uma porta dada.
type fakeSynProbe struct {
	openPort int
	failOpen bool
}

func (f *fakeSynProbe) Open() error {
	if f.failOpen {
		return errors.New("operation not permitted")
	}
	return nil
}
func (f *fakeSynProbe) IsOpen(host string, port int) (bool, error) {
	return port == f.openPort, nil
}
func (f *fakeSynProbe) Close() error { return nil }

// @spec:AC-052 — SYN scan reporta porta aberta
func TestSynScanReportsOpenPort(t *testing.T) {
	scanner := NewSynScanner(5, time.Second)
	scanner.Probe = &fakeSynProbe{openPort: 443}

	results, err := scanner.ScanSYN("10.0.0.5", []int{80, 443, 8080})
	if err != nil {
		t.Fatalf("AC-052: scan: %v", err)
	}
	found := false
	for _, r := range results {
		if r.Port == 443 && r.State == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-052: expected port 443 open, got %+v", results)
	}
}

// @spec:AC-053 — sem privilégio, erro claro pedindo root
func TestSynScanNoPrivilegeClearError(t *testing.T) {
	scanner := NewSynScanner(5, time.Second)
	scanner.Probe = &fakeSynProbe{failOpen: true}

	_, err := scanner.ScanSYN("10.0.0.5", []int{80})
	if err == nil {
		t.Fatalf("AC-053: expected error without privilege, got nil")
	}
	msg := fmt.Sprintf("%v", err)
	if !strings.Contains(msg, "root") && !strings.Contains(msg, "privileg") {
		t.Errorf("AC-053: error should mention root/privilege, got %q", msg)
	}
}