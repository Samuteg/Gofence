package data

import (
	"sync"
	"testing"
)

// @spec:ipcache — ResolveIP memoiza resoluções por processo: chamar duas
// vezes o mesmo host produz o mesmo resultado sem nova query.
func TestResolveIPCacheHit(t *testing.T) {
	ResetIPCache()
	defer ResetIPCache()

	// IP literal passa direto (ParseIP no hostToIP; ResolveIP também aceita).
	first := ResolveIP("127.0.0.1")
	if first != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %q", first)
	}

	// Cache deve conter a entrada.
	if _, ok := ipCache.Load("127.0.0.1"); !ok {
		t.Errorf("expected 127.0.0.1 to be cached after ResolveIP")
	}

	// Segunda chamada serve do cache (mesmo valor).
	if again := ResolveIP("127.0.0.1"); again != first {
		t.Errorf("expected cached %q, got %q", first, again)
	}
}

// @spec:ipcache — falha de resolução também é memoizada (host inválido não
// dispara queries repetidas nos loops de persistência).
func TestResolveIPCacheFailureMemoized(t *testing.T) {
	ResetIPCache()
	defer ResetIPCache()

	ResolveIP("inexistente.gofence.invalid")
	if _, ok := ipCache.Load("inexistente.gofence.invalid"); !ok {
		t.Errorf("expected failed resolution to be memoized (empty result)")
	}
}

// @spec:ipcache — ResetIPCache limpa todas as entradas.
func TestResetIPCache(t *testing.T) {
	ResetIPCache()
	ipCache.Store("a", "1")
	ipCache.Store("b", "2")
	ResetIPCache()
	if _, ok := ipCache.Load("a"); ok {
		t.Errorf("expected cache to be empty after ResetIPCache")
	}
	var n int
	ipCache.Range(func(_, _ interface{}) bool { n++; return true })
	if n != 0 {
		t.Errorf("expected 0 entries, got %d", n)
	}
}

// @spec:ipcache — cache é concorrente-safe (sanity sob -race).
func TestResolveIPCacheConcurrent(t *testing.T) {
	ResetIPCache()
	defer ResetIPCache()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ResolveIP("127.0.0.1")
			ResetIPCache()
		}()
	}
	wg.Wait()
}

// @spec:s3-persist — SaveFinding com ip=hostname único cria hosts distintos
// (regressão do colapso de buckets s3 numa única linha).
func TestSaveFindingUniqueHostKeys(t *testing.T) {
	db, err := New(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	wsID, err := db.WorkspaceCreate("S3Test")
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}

	if err := db.SaveFinding(wsID, "bucket-a", "bucket-a", "medium", "open s3 bucket", "d=a"); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := db.SaveFinding(wsID, "bucket-b", "bucket-b", "medium", "open s3 bucket", "d=b"); err != nil {
		t.Fatalf("save b: %v", err)
	}
	// Repetir bucket-a: upsert, não duplica.
	if err := db.SaveFinding(wsID, "bucket-a", "bucket-a", "medium", "open s3 bucket", "d=a2"); err != nil {
		t.Fatalf("save a2: %v", err)
	}

	hosts, err := db.Hosts(wsID)
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 distinct host rows (bucket-a, bucket-b), got %d", len(hosts))
	}
}
