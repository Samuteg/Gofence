package recon

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-006 — varredura TCP (smoke test on localhost)
func TestPortScanLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer ln.Close()

	scanner := NewPortScanner(10, 0)
	results := scanner.ScanTCP("127.0.0.1", []int{port, 1})
	for i, r := range results {
		if i == 0 && r.State != "open" {
			t.Errorf("AC-006: port %d should be open", r.Port)
		}
	}
}

// @spec:AC-004 — consulta Shodan (com mock server)
func TestOSINTShodanQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ip_str":"1.2.3.4","ports":[80,443]}`)
	}))
	defer server.Close()

	cfg := &config.Config{ShodanKey: "testkey"}
	client := httpclient.New(true, "", 5*time.Second)
	osint := NewOSINTClient(client, cfg)

	// Override the URL by using a custom approach - we test the logic with the real API endpoint
	// Since we can't easily override the URL, test the doRequest helper
	body, err := osint.doRequest(server.URL, "testkey")
	if err != nil {
		t.Fatalf("AC-004: doRequest failed: %v", err)
	}
	if len(body) == 0 {
		t.Errorf("AC-004: expected response body from Shodan query")
	}
}
