package recon

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ScriptResult é o resultado de um script NSE-lite rodado contra um serviço.
type ScriptResult struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
}

// ScriptFunc executa uma checagem contra um host/porta. Deve ser
// não-destrutiva e respeitar timeouts internos.
type ScriptFunc func(host string, port int) ScriptResult

var (
	scriptsMu sync.RWMutex
	scripts   = map[string]map[string]ScriptFunc{} // service -> name -> fn
)

// RegisterScript registra um script para um serviço (ex.: "ssh").
func RegisterScript(service, name string, fn ScriptFunc) {
	scriptsMu.Lock()
	defer scriptsMu.Unlock()
	if scripts[service] == nil {
		scripts[service] = map[string]ScriptFunc{}
	}
	scripts[service][name] = fn
}

// RunScripts executa todos os scripts registrados para o serviço, em ordem
// alfabética de nome. Sem scripts para o serviço, retorna vazio.
func RunScripts(host string, port int, service string) []ScriptResult {
	scriptsMu.RLock()
	fns := make(map[string]ScriptFunc, len(scripts[service]))
	for n, f := range scripts[service] {
		fns[n] = f
	}
	scriptsMu.RUnlock()

	if len(fns) == 0 {
		return nil
	}
	names := make([]string, 0, len(fns))
	for n := range fns {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]ScriptResult, 0, len(names))
	for _, n := range names {
		out = append(out, fns[n](host, port))
	}
	return out
}

// bannerProbe conecta e lê a resposta inicial do serviço (timeout curto).
func bannerProbe(host string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}