package recon

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

// @spec:AC-061 — -oX gera XML compatível com nmap
func TestWriteNmapXML(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scan.xml")

	results := []PortResult{
		{Host: "10.0.0.5", Port: 22, State: "open", Service: "ssh", Version: "8.9p1"},
		{Host: "10.0.0.5", Port: 80, State: "open", Service: "http"},
	}
	if err := WriteNmapXML(out, results); err != nil {
		t.Fatalf("AC-061: write xml: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("AC-061: read xml: %v", err)
	}

	// Parseia como XML válido e confere a estrutura host/ports.
	var run nmapRunXML
	if err := xml.Unmarshal(data, &run); err != nil {
		t.Fatalf("AC-061: parse xml: %v", err)
	}
	if run.Scanner != "gofence" {
		t.Errorf("AC-061: expected scanner gofence, got %q", run.Scanner)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("AC-061: expected 1 host, got %d", len(run.Hosts))
	}
	if run.Hosts[0].Address.Addr != "10.0.0.5" {
		t.Errorf("AC-061: expected address 10.0.0.5, got %q", run.Hosts[0].Address.Addr)
	}
	if len(run.Hosts[0].Ports.Ports) != 2 {
		t.Fatalf("AC-061: expected 2 ports, got %d", len(run.Hosts[0].Ports.Ports))
	}
	if run.Hosts[0].Ports.Ports[0].PortID != 22 || run.Hosts[0].Ports.Ports[0].State.State != "open" {
		t.Errorf("AC-061: unexpected port entry: %+v", run.Hosts[0].Ports.Ports[0])
	}
}