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

// @spec:AC-058 — shorthands nmap -iL/-oX são normalizados antes do parse
func TestNormalizeNmapFlags(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"port", "-iL", "alvos.txt"}, []string{"port", "--iL", "alvos.txt"}},
		{[]string{"port", "-iL=alvos.txt"}, []string{"port", "--iL=alvos.txt"}},
		{[]string{"port", "-iLalvos.txt"}, []string{"port", "--iL=alvos.txt"}},
		{[]string{"port", "-oX", "scan.xml"}, []string{"port", "--oX", "scan.xml"}},
		{[]string{"port", "-oX=scan.xml"}, []string{"port", "--oX=scan.xml"}},
		{[]string{"port", "127.0.0.1", "--ports", "80"}, []string{"port", "127.0.0.1", "--ports", "80"}},
	}
	for _, c := range cases {
		got := normalizeNmapFlags(c.in)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("AC-058: normalizeNmapFlags(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// @spec:AC-058 — -iL sozinho (sem alvo posicional) resolve os alvos
func TestResolveTargetsFromInputListOnly(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "only.txt")
	if err := os.WriteFile(listFile, []byte("10.0.0.9\n"), 0644); err != nil {
		t.Fatalf("AC-058: write: %v", err)
	}
	targets, err := resolvePortTargets("", listFile)
	if err != nil {
		t.Fatalf("AC-058: resolve: %v", err)
	}
	if len(targets) != 1 || targets[0] != "10.0.0.9" {
		t.Errorf("AC-058: expected [10.0.0.9], got %v", targets)
	}
}