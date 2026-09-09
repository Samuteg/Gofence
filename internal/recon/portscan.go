package recon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortResult struct {
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
}

var commonServices = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	111:  "rpcbind",
	135:  "msrpc",
	139:  "netbios-ssn",
	143:  "imap",
	443:  "https",
	445:  "microsoft-ds",
	993:  "imaps",
	995:  "pop3s",
	1433: "mssql",
	1521: "oracle",
	3306: "mysql",
	3389: "ms-wbt-server",
	5432: "postgresql",
	5900: "vnc",
	6379: "redis",
	8080: "http-proxy",
	8443: "https-alt",
	9000: "sonarqube",
	9200: "elasticsearch",
	27017: "mongodb",
}

// bannerPatterns identifica serviço+versão a partir do banner lido na porta
// aberta. Ordem importa: o primeiro padrão que casa vence.
var bannerPatterns = []struct {
	service string
	re      *regexp.Regexp
}{
	// HTTP: depois de enviar GET, o Server: header dá o produto (ex.: nginx/1.18)
	{"http", regexp.MustCompile(`(?i)^HTTP/\d+\.\d+[\s\S]*?\r?\nServer:\s*([^\r\n]+)`)},

	// SSH: "SSH-2.0-OpenSSH_8.9p1" → versão "8.9p1"; "SSH-2.0-dropbear_2022.83" → "2022.83"
	{"ssh", regexp.MustCompile(`(?i)^SSH-\d+\.\d+-(?:OpenSSH_)?([^\s\r\n]+)`)},
	{"smtp", regexp.MustCompile(`(?i)^220[- ]([^\r\n]*)`)},
	{"pop3", regexp.MustCompile(`(?i)^\+OK\s*([^\r\n]*)`)},
	{"imap", regexp.MustCompile(`(?i)^\*\s*OK\s*([^\r\n]*)`)},
	{"telnet", regexp.MustCompile(`(?i)^\xff\xfd\x18[^\r\n]*`)},
}

type PortScanner struct {
	Concurrency int
	Timeout     time.Duration
	Retries     int
	// Dial é injetável para testes herméticos (retry/erros transientes).
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)
	// BannerRead é injetável para testes; default lê a resposta inicial.
	BannerRead func(conn net.Conn, timeout time.Duration) string
}

func NewPortScanner(concurrency int, timeout time.Duration) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ps := &PortScanner{Concurrency: concurrency, Timeout: timeout}
	ps.Dial = net.DialTimeout
	ps.BannerRead = readBanner
	return ps
}

// ExpandCIDR expands a CIDR into its individual host addresses (IPv4/IPv6).
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	var hosts []string
	cur := ip.Mask(ipNet.Mask)
	for ipNet.Contains(cur) {
		hosts = append(hosts, cur.String())
		cur = nextIP(cur)
	}
	return hosts, nil
}

func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// ScanTCP varre um único alvo (hostname, IP ou ip:porta).
func (ps *PortScanner) ScanTCP(target string, ports []int) []PortResult {
	return ps.ScanTCPHosts([]string{target}, ports)
}

// ScanTCPHosts varre cada alvo da lista (hosts individuais, nunca CIDR —
// expanda antes com ExpandCIDR) e rotula cada resultado com o Host.
func (ps *PortScanner) ScanTCPHosts(targets []string, ports []int) []PortResult {
	return ps.ScanTCPHostsContext(context.Background(), targets, ports)
}

// ScanTCPHostsContext é o ScanTCPHosts com cancelamento: parado o ctx,
// nenhuma nova porta é enfileirada e os resultados parciais são retornados.
func (ps *PortScanner) ScanTCPHostsContext(ctx context.Context, targets []string, ports []int) []PortResult {
	if len(targets) == 0 {
		return nil
	}
	sem := make(chan struct{}, ps.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []PortResult
	canceled := false

	for _, target := range targets {
		for _, port := range ports {
			if ctx.Err() != nil {
				canceled = true
				break
			}
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				canceled = true
			}
			if canceled {
				break
			}
			go func(t string, p int) {
				defer wg.Done()
				defer func() { <-sem }()
				state, svc, ver := ps.scanTCPPort(t, p)
				if state == "open" {
					mu.Lock()
					results = append(results, PortResult{
						Host:    t,
						Port:    p,
						State:   "open",
						Service: svc,
						Version: ver,
					})
					mu.Unlock()
				}
			}(target, port)
		}
		if canceled {
			break
		}
	}
	wg.Wait()
	return results
}

// scanTCPPort tenta conectar (com retries) e, em caso de sucesso, tenta
// identificar serviço/versão pelo banner. Retorna estado, serviço e versão.
func (ps *PortScanner) scanTCPPort(target string, port int) (string, string, string) {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	attempts := ps.Retries + 1
	for i := 0; i < attempts; i++ {
		conn, err := ps.Dial("tcp", addr, ps.Timeout)
		if err == nil {
			banner := ps.BannerRead(conn, ps.Timeout)
			conn.Close()
			svc, ver := IdentifyService(port, banner)
			return "open", svc, ver
		}
	}
	return "closed", "", ""
}

// IdentifyService mapeia banner+porta para (serviço, versão). Sem banner,
// cai no mapa estático de portas comuns (versão vazia).
func IdentifyService(port int, banner string) (string, string) {
	if strings.TrimSpace(banner) != "" {
		for _, bp := range bannerPatterns {
			if m := bp.re.FindStringSubmatch(banner); m != nil {
				return bp.service, strings.TrimSpace(m[1])
			}
		}
	}
	return commonServices[port], ""
}

func readBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	var sb strings.Builder
	buf := make([]byte, 256)
	for sb.Len() < 4096 {
		n, err := reader.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

func (ps *PortScanner) ScanUDP(target string, ports []int) []PortResult {
	return ps.ScanUDPContext(context.Background(), target, ports)
}

// ScanUDPContext é o ScanUDP com cancelamento (retorna parciais).
func (ps *PortScanner) ScanUDPContext(ctx context.Context, target string, ports []int) []PortResult {
	var results []PortResult
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		addr := net.JoinHostPort(target, strconv.Itoa(port))
		conn, err := ps.Dial("udp", addr, ps.Timeout)
		if err != nil {
			continue
		}
		conn.SetReadDeadline(time.Now().Add(ps.Timeout))
		_, err = conn.Write([]byte("\x00"))
		if err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		conn.Close()
		if err == nil {
			results = append(results, PortResult{Port: port, State: "open", Service: commonServices[port]})
		} else {
			results = append(results, PortResult{Port: port, State: "filtered", Service: commonServices[port]})
		}
	}
	return results
}

func TopPorts(n int) []int {
	common := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200, 27017}
	if n > len(common) {
		return common
	}
	return common[:n]
}

func TopUDPPorts(n int) []int {
	common := []int{53, 67, 68, 69, 123, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434}
	if n > len(common) {
		return common
	}
	return common[:n]
}