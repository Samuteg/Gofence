package ux

import (
	"bytes"
	"encoding/json"
	"os"
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
