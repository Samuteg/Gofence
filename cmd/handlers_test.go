package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nixteg/gofence/internal/data"
)

// wireTestDB cria banco temporário com workspace "Teste" e escopo dado,
// apontando os globals do pacote (dbPath, workspaceName) para ele.
func wireTestDB(t *testing.T, cidrs ...string) {
	t.Helper()
	testDB := filepath.Join(t.TempDir(), "test.db")
	if err := os.Unsetenv("GOFENCE_DB_PATH"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	db, err := data.New(testDB)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	wsID, err := db.WorkspaceCreate("Teste")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	for _, c := range cidrs {
		if err := db.ScopeAdd(wsID, c, "allowed"); err != nil {
			t.Fatalf("add scope: %v", err)
		}
	}

	oldDB, oldWS := dbPath, workspaceName
	dbPath, workspaceName = testDB, "Teste"
	t.Cleanup(func() {
		dbPath, workspaceName = oldDB, oldWS
		db.Close()
	})
}

// ---- workspace ----

// @spec:workspace-cli — new/list/scope/set-active end-to-end contra banco temporário
func TestWorkspaceLifecycle(t *testing.T) {
	wireTestDB(t) // sem escopo: só para o lifecycle

	if err := workspaceNew.RunE(workspaceNew, []string{"EngX"}); err != nil {
		t.Fatalf("workspace new: %v", err)
	}
	if err := workspaceScope.RunE(workspaceScope, []string{"EngX", "10.50.0.0/16"}); err != nil {
		t.Fatalf("workspace scope: %v", err)
	}
	if err := workspaceSetActive.RunE(workspaceSetActive, []string{"EngX"}); err != nil {
		t.Fatalf("set-active: %v", err)
	}
	// set-active em workspace inexistente falha.
	if err := workspaceSetActive.RunE(workspaceSetActive, []string{"NaoExiste"}); err == nil {
		t.Errorf("expected error setting active to unknown workspace")
	}
}

// @spec:workspace-cli — scope com CIDR inválido é recusado pelo data layer
func TestWorkspaceScopeInvalidCIDR(t *testing.T) {
	wireTestDB(t)
	if err := workspaceNew.RunE(workspaceNew, []string{"BadScope"}); err != nil {
		t.Fatalf("workspace new: %v", err)
	}
	if err := workspaceScope.RunE(workspaceScope, []string{"BadScope", "nao-e-cidr"}); err == nil {
		t.Errorf("expected error for invalid CIDR, got nil")
	}
}

// ---- report ----

// @spec:report-cli — report gera markdown e json sem erro com dados no banco
func TestReportFormats(t *testing.T) {
	wireTestDB(t, "10.0.0.0/8")

	if err := workspaceNew.RunE(workspaceNew, []string{"RepWS"}); err != nil {
		t.Fatalf("workspace new: %v", err)
	}
	if err := workspaceScope.RunE(workspaceScope, []string{"RepWS", "10.0.0.0/8"}); err != nil {
		t.Fatalf("workspace scope: %v", err)
	}
	if err := workspaceSetActive.RunE(workspaceSetActive, []string{"RepWS"}); err != nil {
		t.Fatalf("set-active: %v", err)
	}

	db, err := openDB()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	wsID, err := db.ActiveWorkspace("RepWS")
	if err != nil {
		t.Fatalf("active ws: %v", err)
	}
	if err := db.SaveFinding(wsID, "10.0.0.9", "host.repw", "high", "test finding", "detail=x"); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	db.Close()

	oldFmt := reportFormat
	t.Cleanup(func() { reportFormat = oldFmt })

	reportFormat = "md"
	if err := reportCmd.RunE(reportCmd, nil); err != nil {
		t.Fatalf("report md: %v", err)
	}

	reportFormat = "json"
	if err := reportCmd.RunE(reportCmd, nil); err != nil {
		t.Fatalf("report json: %v", err)
	}
}

// @spec:report-cli — --format inválido cai no markdown (comportamento atual)
func TestReportInvalidFormat(t *testing.T) {
	wireTestDB(t, "10.0.0.0/8")
	oldFmt := reportFormat
	reportFormat = "xml"
	t.Cleanup(func() { reportFormat = oldFmt })

	// Não pode panicar; saída é markdown (fallback).
	if err := reportCmd.RunE(reportCmd, nil); err != nil {
		t.Fatalf("report xml: %v", err)
	}
}

// ---- payload ----

// @spec:payload-cli — payload válido gera one-liner sem erro
func TestPayloadGeneration(t *testing.T) {
	oldType, oldIP, oldPort, oldBind := payloadType, payloadIP, payloadPort, payloadBind
	t.Cleanup(func() { payloadType, payloadIP, payloadPort, payloadBind = oldType, oldIP, oldPort, oldBind })

	cases := []struct{ ptype, ip string; port int }{
		{"bash", "10.0.0.1", 4444},
		{"nc", "10.0.0.1", 4444},
		{"python", "10.0.0.1", 4444},
	}
	for _, c := range cases {
		payloadType, payloadIP, payloadPort, payloadBind = c.ptype, c.ip, c.port, false
		if err := payloadCmd.RunE(payloadCmd, nil); err != nil {
			t.Errorf("payload %s: %v", c.ptype, err)
		}
	}

	// Bind shell
	payloadType, payloadIP, payloadPort, payloadBind = "nc", "", 9999, true
	if err := payloadCmd.RunE(payloadCmd, nil); err != nil {
		t.Errorf("payload bind: %v", err)
	}
}

// @spec:payload-cli — tipo inválido retorna erro claro
func TestPayloadInvalidType(t *testing.T) {
	oldType := payloadType
	payloadType = "cobaltstrike"
	t.Cleanup(func() { payloadType = oldType })

	if err := payloadCmd.RunE(payloadCmd, nil); err == nil {
		t.Errorf("expected error for invalid payload type, got nil")
	}
}

// ---- recusas de escopo (fail-closed) ----

// @spec:scope-refusal — tls sem workspace ativo recusa antes de conectar
func TestTLSCommandNoWorkspace(t *testing.T) {
	wireTestDB(t) // workspace "Teste" sem escopo → empty scope blocks

	if err := tlsCmd.RunE(tlsCmd, []string{"127.0.0.1:443"}); err == nil {
		t.Errorf("expected error with empty scope, got nil")
	}
}

// @spec:scope-refusal — dns sem workspace ativo recusa antes de resolver
func TestDNSCommandNoWorkspace(t *testing.T) {
	wireTestDB(t)

	err := dnsCmd.RunE(dnsCmd, []string{"inexistente.gofence.invalid"})
	if err == nil {
		t.Fatalf("expected error with empty scope, got nil")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Errorf("expected scope-related error, got: %v", err)
	}
}

// @spec:scope-refusal — osint sem workspace ativo segue sem persistir mas executa?:
// não — openWorkspace retorna (nil,0) e requireScope falha; comando recusa.
func TestOSINTCommandNoWorkspace(t *testing.T) {
	wireTestDB(t)

	if err := osintCmd.RunE(osintCmd, []string{"127.0.0.1"}); err == nil {
		t.Errorf("expected error with empty scope, got nil")
	}
}
