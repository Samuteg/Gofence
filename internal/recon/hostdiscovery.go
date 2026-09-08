package recon

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// PingSweep descobre quais hosts de uma lista estão vivos usando probe TCP
// nas portas dadas (conexão bem-sucedida = host vivo). Retorna os hosts vivos,
// na mesma ordem relativa da entrada.
func (ps *PortScanner) PingSweep(targets []string, probePorts []int) []string {
	if len(targets) == 0 {
		return nil
	}
	sem := make(chan struct{}, ps.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	alive := make([]string, 0, len(targets))

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ps.hostAlive(host, probePorts) {
				mu.Lock()
				alive = append(alive, host)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return alive
}

func (ps *PortScanner) hostAlive(host string, probePorts []int) bool {
	for _, p := range probePorts {
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		conn, err := ps.Dial("tcp", addr, time.Duration(float64(ps.Timeout)*0.5))
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}