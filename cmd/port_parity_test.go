package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// @spec:AC-058 — alvos de arquivo são varridos um a um
func TestResolveTargetsFromInputList(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "targets.txt")
	content := "# comentário\n10.0.0.1\n10.0.0.0/31\n\n"
	if err := os.WriteFile(listFile, []byte(content), 0644); err != nil {
		t.Fatalf("AC-058: write list: %v", err)
	}

	targets, err := resolvePortTargets("", listFile)
	if err != nil {
		t.Fatalf("AC-058: resolve: %v", err)
	}

	// 10.0.0.1 + expansão de 10.0.0.0/31 (2 hosts) = 3 alvos; comentário e
	// linha vazia ignorados.
	if len(targets) != 3 {
		t.Fatalf("AC-058: expected 3 targets (1 literal + 2 from /31), got %v", targets)
	}
	joined := strings.Join(targets, ",")
	if !strings.Contains(joined, "10.0.0.1") || !strings.Contains(joined, "10.0.0.0") || !strings.Contains(joined, "10.0.0.1,") {
		t.Errorf("AC-058: missing expected hosts in %v", targets)
	}
}