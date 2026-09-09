package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// writeTempWL cria wordlist temporária com as palavras dadas.
func writeTempWL(t *testing.T, words []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wl.txt")
	if err := os.WriteFile(p, []byte(joinLines(words)), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	return p
}

func joinLines(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += "\n"
		}
		out += w
	}
	return out + "\n"
}

func wordsList() []string {
	return []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"}
}

// @spec:fuzz-cancel — ctx cancelado (simula Ctrl+C) encerra a wave sem hang:
// o canal de resultados fecha e o FuzzWeb retorna em tempo finito, sem
// processar a wordlist inteira.
func TestFuzzWebCancelStopsWave(t *testing.T) {
	var hits int64
	release := make(chan struct{})
	var closeOnce sync.Once
	doClose := func() { closeOnce.Do(func() { close(release) }) }
	defer doClose()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		<-release // trava a resposta até o teste destravar
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wl := writeTempWL(t, wordsList())
	client := httpclient.New(false, "", 2*time.Second)
	fuzzer := NewFuzzer(client, 1)
	fuzzer.Progress = false
	fuzzer.Limiter = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, err := fuzzer.FuzzWeb(ctx, srv.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("FuzzWeb: %v", err)
	}

	// Espera as requisições chegarem ao handler (wildcard + worker) e
	// cancela com elas ainda travadas: nada além disso deve ser processado.
	time.Sleep(100 * time.Millisecond)
	cancel()
	doClose() // destrava as pendentes; producer deve sair do loop

	// O canal DEVE fechar (produtor saiu do loop) em tempo finito.
	for range results {
	}
	if h := atomic.LoadInt64(&hits); h > 4 {
		t.Errorf("expected wave to stop early after cancel (<=4 requests), got %d of %d words", h, len(wordsList()))
	}
}

// @spec:fuzz-cancel — sem cancelamento, a wave processa tudo (sanity check
// do teste acima: o travamento não vaza requisições).
func TestFuzzWebNoCancelCompletesAll(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	wl := writeTempWL(t, wordsList())
	client := httpclient.New(false, "", 2*time.Second)
	fuzzer := NewFuzzer(client, 4)
	fuzzer.Progress = false
	fuzzer.Limiter = nil

	results, err := fuzzer.FuzzWeb(context.Background(), srv.URL+"/FUZZ", wl, "", "")
	if err != nil {
		t.Fatalf("FuzzWeb: %v", err)
	}
	for range results {
	}
	// 16 palavras + 1 sonda wildcard.
	if h := atomic.LoadInt64(&hits); h != int64(len(wordsList())+1) {
		t.Errorf("expected %d hits, got %d", len(wordsList())+1, h)
	}
}
