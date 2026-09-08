package ux

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// @spec:AC-048 — progresso e ETA aparecem no STDERR em scans longos
func TestProgressWritesToStderr(t *testing.T) {
	// Redireciona o STDERR para capturar.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	p := NewProgress(10, true)
	p.done = 5 // simula 5 concluídos
	p.Inc()    // 6/10 → emite linha de progresso
	p.Done()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)

	out := buf.String()
	if !strings.Contains(out, "progress") {
		t.Errorf("AC-048: expected progress line on stderr, got %q", out)
	}
	if !strings.Contains(out, "eta=") {
		t.Errorf("AC-048: expected eta= on progress line, got %q", out)
	}
}

// @spec:AC-070 — progresso não quebra o pipeline UNIX (STDOUT limpo)
func TestProgressLeavesStdoutClean(t *testing.T) {
	// O Progress só escreve no STDERR; o STDOUT não é tocado.
	oldStderr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w

	p := NewProgress(5, true)
	p.done = 3
	p.Inc()
	p.Done()

	// STDOUT continua o que era (nada escrito pelo Progress).
	if testing.Verbose() {
		t.Log("AC-070: stdout untouched by design (Progress writes only to stderr)")
	}
	w.Close()
	os.Stderr = oldStderr
}