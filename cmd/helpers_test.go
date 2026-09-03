package cmd

import (
	"path/filepath"
	"testing"

	"github.com/nixteg/gofence/internal/data"
)

func testDBWithScope(t *testing.T, cidrs ...string) (*data.DB, int64) {
	t.Helper()
	db, err := data.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	wsID, err := db.WorkspaceCreate("Teste")
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}
	for _, c := range cidrs {
		if err := db.ScopeAdd(wsID, c, "allowed"); err != nil {
			t.Fatalf("failed to add scope: %v", err)
		}
	}
	return db, wsID
}

// @spec:AC-037 — sem workspace ativo o comando recusa com orientação
func TestRequireScopeNoWorkspace(t *testing.T) {
	if err := requireScope(nil, 0, "10.0.0.1", "test"); err == nil {
		t.Errorf("AC-037: expected error without active workspace, got nil")
	}
}

// @spec:AC-038 — workspace com escopo vazio bloqueia tudo
func TestRequireScopeEmptyScope(t *testing.T) {
	db, wsID := testDBWithScope(t)
	if err := requireScope(db, wsID, "10.0.0.1", "test"); err == nil {
		t.Errorf("AC-038: expected error with empty scope, got nil")
	}
}

// @spec:AC-036 — alvo dentro do escopo passa; fora é recusado
func TestRequireScopeInScope(t *testing.T) {
	db, wsID := testDBWithScope(t, "10.0.0.0/8")
	if err := requireScope(db, wsID, "10.0.1.5", "test"); err != nil {
		t.Errorf("AC-036: expected nil for in-scope target, got %v", err)
	}
	if err := requireScope(db, wsID, "192.168.1.1", "test"); err == nil {
		t.Errorf("AC-035: expected error for out-of-scope target, got nil")
	}
}
