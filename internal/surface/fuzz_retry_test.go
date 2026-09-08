package surface

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-071 — erro de conexão é retentado antes de descartar
func TestFuzzerRetryTransportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	// Conta as conexões e derruba as duas primeiras com reset.
	var calls int32
	client := httpclient.NewFromEnv()
	client.HTTP.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			return nil, fmt.Errorf("connection reset by peer (attempt %d)", n)
		}
		return net.Dial(network, addr)
	}

	wl := writeWordlist(t, "probe")
	fuzzer := NewFuzzer(client, 5)
	fuzzer.Retries = 3 // até 3 tentativas extras antes de desistir

	results, err := fuzzer.FuzzWeb(context.Background(), server.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("AC-071: fuzz: %v", err)
	}
	out := collect(results)
	if len(out) == 0 {
		t.Fatalf("AC-071: expected result after retries (calls=%d), got none", calls)
	}
	if calls < 3 {
		t.Errorf("AC-071: expected retry (>=3 dial calls), got %d", calls)
	}
}