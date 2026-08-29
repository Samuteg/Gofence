package data

import (
	"path/filepath"
	"testing"
)

// @spec:AC-023 — criação de workspace
func TestWorkspaceCreate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("AC-023: failed to open db: %v", err)
	}
	defer db.Close()

	id, err := db.WorkspaceCreate("Cliente X")
	if err != nil {
		t.Fatalf("AC-023: failed to create workspace: %v", err)
	}
	if id <= 0 {
		t.Errorf("AC-023: expected positive workspace ID, got %d", id)
	}
}

// @spec:AC-024 — persistência de hosts
func TestHostUpsert(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("AC-024: failed to open db: %v", err)
	}
	defer db.Close()

	wsID, _ := db.WorkspaceCreate("test")
	id, err := db.HostUpsert(wsID, "10.0.0.5", "host.example.com")
	if err != nil {
		t.Fatalf("AC-024: failed to upsert host: %v", err)
	}
	if id <= 0 {
		t.Errorf("AC-024: expected positive host ID, got %d", id)
	}

	// Re-upsert same IP should not fail (ON CONFLICT)
	id2, err := db.HostUpsert(wsID, "10.0.0.5", "host2.example.com")
	if err != nil {
		t.Fatalf("AC-024: re-upsert should not fail: %v", err)
	}
	if id != id2 {
		t.Errorf("AC-024: re-upsert should return same ID, got %d != %d", id, id2)
	}
}

// @spec:AC-025 — persistência de findings
func TestFindingCreate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("AC-025: failed to open db: %v", err)
	}
	defer db.Close()

	wsID, _ := db.WorkspaceCreate("test")
	hostID, _ := db.HostUpsert(wsID, "10.0.0.5", "host")

	err = db.FindingCreate(hostID, "high", "SQL Injection", `{"url":"/login"}`)
	if err != nil {
		t.Fatalf("AC-025: failed to create finding: %v", err)
	}
}
