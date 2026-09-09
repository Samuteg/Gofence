package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/ux"
)

// openWorkspace opens the DB and resolves the active workspace. Returns (nil, 0)
// when persistence is unavailable (no DB or no active workspace) so callers can
// skip saving findings gracefully instead of failing the whole scan.
func openWorkspace() (*data.DB, int64) {
	p := effDBPath()
	db, err := data.New(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: cannot open db (%v); findings not persisted\n", err)
		return nil, 0
	}
	wsID, err := db.ActiveWorkspace(workspaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: %v; findings not persisted\n", err)
		db.Close()
		return nil, 0
	}
	return db, wsID
}

// mustScope validates fail-closed scope and returns the guard: it errors
// when there is no active workspace or the workspace scope is empty.
func mustScope(db *data.DB, wsID int64) (*data.ScopeGuard, error) {
	if db == nil {
		return nil, fmt.Errorf("no active workspace; create one and add scope ('workspace new' + 'workspace scope') or pass --workspace")
	}
	guard, err := data.GuardForWorkspace(db, wsID)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	if guard.Empty() {
		return nil, fmt.Errorf("workspace has no scope CIDRs; add one with 'workspace scope'")
	}
	return guard, nil
}

// requireScope blocks the command when host is out of scope (already logged
// as Out-of-Scope Blocked) or when scope cannot be evaluated (fail-closed).
func requireScope(db *data.DB, wsID int64, host, action string) error {
	guard, err := mustScope(db, wsID)
	if err != nil {
		return err
	}
	if !data.CheckHost(guard, host, action) {
		return fmt.Errorf("target %s is out of scope", host)
	}
	return nil
}

// stdinTarget resolves the command target from the positional arg or, when
// absent, from piped stdin (first line). Extra lines are reported on stderr.
func stdinTarget(args []string) (string, error) {
	target, rest, err := ux.ResolveTarget(args, os.Stdin, ux.StdinPiped())
	if err != nil {
		return "", err
	}
	if rest > 0 {
		fmt.Fprintf(os.Stderr, "warn: ignoring %d extra piped line(s); using %s\n", rest, target)
	}
	return target, nil
}

// hostOf extrai host[:porta] de um alvo que pode ser URL ou host nu.
// Canonical: mesma semântica de data.HostOf (usada pelo scope), mantida aqui
// para os formatadores de saída.
func hostOf(target string) string {
	return data.HostOf(target)
}

func writeTempWordlist(words []string, name string) (string, error) {
	f, err := os.CreateTemp("", "gofence-"+name+"-*.txt")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(strings.Join(words, "\n") + "\n"); err != nil {
		f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}
