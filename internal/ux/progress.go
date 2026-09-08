package ux

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Progress reporta avanço (concluído/total, % e ETA) no STDERR, no máximo
// uma linha por segundo e a cada 1% de avanço. O STDOUT fica intocado.
type Progress struct {
	mu      sync.Mutex
	total   int
	done    int
	start   time.Time
	lastAt  time.Time
	lastPct int
	enabled bool
}

// NewProgress cria um reporte de progresso para `total` itens.
func NewProgress(total int, enabled bool) *Progress {
	return &Progress{
		total:   total,
		start:   time.Now(),
		lastAt:  time.Now(),
		enabled: enabled,
	}
}

// Inc avança o contador em um e emite progresso se devido.
func (p *Progress) Inc() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return
	}
	p.done++
	if p.total <= 0 {
		return
	}
	pct := p.done * 100 / p.total
	now := time.Now()
	// No máximo 1 linha/segundo e a cada ~1% de avanço.
	if now.Sub(p.lastAt) < time.Second && pct <= p.lastPct {
		return
	}
	p.lastAt = now
	p.lastPct = pct
	fmt.Fprintf(os.Stderr, "\r[progress] %d/%d (%d%%) eta=%s", p.done, p.total, pct, p.eta(now))
}

// Done finaliza com a linha final (nova linha no STDERR).
func (p *Progress) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return
	}
	elapsed := time.Since(p.start).Round(time.Second)
	fmt.Fprintf(os.Stderr, "\r[progress] done: %d/%d in %s\n", p.done, p.total, elapsed)
}

func (p *Progress) eta(now time.Time) string {
	if p.done == 0 {
		return "?"
	}
	per := now.Sub(p.start) / time.Duration(p.done)
	remaining := time.Duration(p.total-p.done) * per
	if remaining < 0 {
		remaining = 0
	}
	return remaining.Round(time.Second).String()
}