package ux

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// @spec:AC-030 — saída JSON canalizável
func TestOutputJSONMode(t *testing.T) {
	// When stdout is not a TTY, auto-detect JSON mode
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	mode := DetectOutputMode(false)
	if mode != OutputJSON {
		// restore before failing
		w.Close()
		os.Stdout = oldStdout
		t.Errorf("AC-030: non-TTY stdout should auto-detect JSON mode, got %v", mode)
	}

	data := map[string]string{"key": "value"}
	err := PrintJSON(data)
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("AC-030: PrintJSON failed: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	var decoded map[string]string
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("AC-030: output should be valid JSON: %v", err)
	}
}

// @spec:AC-031 — encadeamento de comandos (pipe input)
func TestPipeInput(t *testing.T) {
	// Simulate piped input
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		w.Write([]byte("10.0.0.1\n10.0.0.2\n"))
		w.Close()
	}()

	lines, err := PipeInput()
	os.Stdin = oldStdin
	if err != nil {
		t.Fatalf("AC-031: PipeInput failed: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("AC-031: expected 2 lines from pipe, got %d", len(lines))
	}
}

// @spec:AC-040 — sem argumento, o alvo vem da primeira linha do stdin
func TestResolveTargetUsesFirstLine(t *testing.T) {
	target, rest, err := ResolveTarget(nil, strings.NewReader("10.0.0.1\n10.0.0.2\n"), true)
	if err != nil {
		t.Fatalf("AC-040: unexpected error: %v", err)
	}
	if target != "10.0.0.1" {
		t.Errorf("AC-040: expected first line as target, got %q", target)
	}
	if rest != 1 {
		t.Errorf("AC-040: expected 1 ignored line, got %d", rest)
	}
}

// @spec:AC-040 — vale o primeiro campo da linha (saída `sub IP` do dns)
func TestResolveTargetUsesFirstField(t *testing.T) {
	target, _, err := ResolveTarget(nil, strings.NewReader("www.alvo.com 10.0.0.1\n"), true)
	if err != nil {
		t.Fatalf("AC-040: unexpected error: %v", err)
	}
	if target != "www.alvo.com" {
		t.Errorf("AC-040: expected first field as target, got %q", target)
	}
}

// @spec:AC-041 — sem argumento e sem pipe, erro de uso
func TestResolveTargetRequiresArgOrPipe(t *testing.T) {
	if _, _, err := ResolveTarget(nil, strings.NewReader(""), false); err == nil {
		t.Errorf("AC-041: expected error without arg and without pipe, got nil")
	}
	if _, _, err := ResolveTarget(nil, strings.NewReader("  \n"), true); err == nil {
		t.Errorf("AC-041: expected error with empty piped stdin, got nil")
	}
}

// @spec:AC-042 — argumento explícito tem prioridade sobre o pipe
func TestResolveTargetArgWins(t *testing.T) {
	target, rest, err := ResolveTarget([]string{"10.9.9.9"}, strings.NewReader("10.0.0.1\n"), true)
	if err != nil {
		t.Fatalf("AC-042: unexpected error: %v", err)
	}
	if target != "10.9.9.9" {
		t.Errorf("AC-042: expected explicit arg as target, got %q", target)
	}
	if rest != 0 {
		t.Errorf("AC-042: expected 0 ignored lines, got %d", rest)
	}
}
