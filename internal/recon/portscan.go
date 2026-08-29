package recon

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
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

type PortScanner struct {
	Concurrency int
	Timeout     time.Duration
}

func NewPortScanner(concurrency int, timeout time.Duration) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &PortScanner{Concurrency: concurrency, Timeout: timeout}
}

func (ps *PortScanner) ScanTCP(target string, ports []int) []PortResult {
	sem := make(chan struct{}, ps.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []PortResult

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			if state := ps.scanTCPPort(target, p); state == "open" {
				mu.Lock()
				results = append(results, PortResult{
					Port:    p,
					State:   "open",
					Service: commonServices[p],
				})
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return results
}

func (ps *PortScanner) scanTCPPort(target string, port int) string {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, ps.Timeout)
	if err != nil {
		return "closed"
	}
	conn.Close()
	return "open"
}

func (ps *PortScanner) ScanUDP(target string, ports []int) []PortResult {
	var results []PortResult
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("udp", addr, ps.Timeout)
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
