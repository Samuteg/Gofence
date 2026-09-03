package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/data"
)

// openWorkspace opens the DB and resolves the active workspace. Returns (nil, 0)
// when persistence is unavailable (no DB or no active workspace) so callers can
// skip saving findings gracefully instead of failing the whole scan.
func openWorkspace() (*data.DB, int64) {
	dbPath := dbPath
	if dbPath == "" {
		dbPath = config.Get().DBPath
	}
	db, err := data.New(dbPath)
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

func hostOf(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if u, err := url.Parse(target); err == nil {
			return u.Host
		}
	}
	return target
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
