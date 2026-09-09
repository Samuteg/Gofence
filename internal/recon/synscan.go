package recon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// SynProbe abstrai o envio de SYN e a detecção de SYN-ACK. O default é o
// rawProbe (raw socket, exige CAP_NET_RAW); testes injetam um fake.
type SynProbe interface {
	// Open prepara o socket. Deve retornar erro claro quando não há
	// privilégio (CAP_NET_RAW ausente).
	Open() error
	// IsOpen verifica se a porta responde com SYN-ACK.
	IsOpen(host string, port int) (bool, error)
	Close() error
}

type SynScanner struct {
	Concurrency int
	Timeout     time.Duration
	Probe       SynProbe
}

func NewSynScanner(concurrency int, timeout time.Duration) *SynScanner {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &SynScanner{Concurrency: concurrency, Timeout: timeout, Probe: &rawProbe{}}
}

// ScanSYN varre as portas com SYN scan. Retorna erro quando o probe não
// consegue abrir o socket raw (sem privilégio) — nunca trava.
func (ss *SynScanner) ScanSYN(target string, ports []int) ([]PortResult, error) {
	return ss.ScanSYNContext(context.Background(), target, ports)
}

// ScanSYNContext é o ScanSYN com cancelamento (retorna parciais).
func (ss *SynScanner) ScanSYNContext(ctx context.Context, target string, ports []int) ([]PortResult, error) {
	if err := ss.Probe.Open(); err != nil {
		return nil, fmt.Errorf("SYN scan requires raw sockets: %w (run as root/sudo or use the default connect scan)", err)
	}
	defer ss.Probe.Close()

	sem := make(chan struct{}, ss.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []PortResult
	canceled := false

	for _, port := range ports {
		if ctx.Err() != nil {
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
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			open, err := ss.Probe.IsOpen(target, p)
			if err != nil {
				return
			}
			if open {
				mu.Lock()
				results = append(results, PortResult{
					Host:    target,
					Port:    p,
					State:   "open",
					Service: commonServices[p],
				})
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return results, nil
}

// rawProbe envia SYN por raw socket (Linux) e detecta SYN-ACK.
type rawProbe struct {
	fd    int
	seq   uint32
	local net.IP
}

func (p *rawProbe) Open() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("open raw socket: %w", err)
	}
	p.fd = fd
	p.seq = uint32(time.Now().UnixNano())
	p.local, _ = localIP()
	return nil
}

func (p *rawProbe) Close() error {
	if p.fd != 0 {
		syscall.Close(p.fd)
	}
	return nil
}

func (p *rawProbe) IsOpen(host string, port int) (bool, error) {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false, fmt.Errorf("SYN scan supports IPv4 targets only (got %q)", host)
	}
	dst := ip.To4()

	p.seq++
	pkt := buildSynPacket(p.local.To4(), dst, uint16(port), p.seq)

	err := syscall.Sendto(p.fd, pkt, 0, &syscall.SockaddrInet4{Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}, Port: 0})
	if err != nil {
		return false, fmt.Errorf("send SYN: %w", err)
	}

	// Espera SYN-ACK na porta alvo (lê pacotes por um curto período).
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		syscall.SetNonblock(p.fd, false)
		n, _, err := syscall.Recvfrom(p.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return false, nil
		}
		if n >= 40 && isSynAck(buf[:n], dst, uint16(port)) {
			return true, nil
		}
	}
	return false, nil
}

// buildSynPacket monta IP + TCP com flag SYN e checksums corretos.
func buildSynPacket(src, dst net.IP, dport uint16, seq uint32) []byte {
	const tcpLen = 20
	pkt := make([]byte, 20+tcpLen)
	// Cabeçalho IP (20 bytes).
	pkt[0] = 0x45
	pkt[1] = 0
	pkt[2] = byte((20 + tcpLen) >> 8)
	pkt[3] = byte(20 + tcpLen)
	pkt[4], pkt[5] = 0, 0 // id
	pkt[6], pkt[7] = 0x40, 0
	pkt[8] = 64
	pkt[9] = syscall.IPPROTO_TCP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	// Checksum IP.
	ipSum := checksum(pkt[0:20])
	pkt[10] = byte(ipSum >> 8)
	pkt[11] = byte(ipSum)

	// Cabeçalho TCP (20 bytes, sem opções).
	tcp := pkt[20:]
	copy(tcp[0:2], []byte{0, 0}) // sport 0 (kernel usa a interface)
	tcp[2] = byte(dport >> 8)
	tcp[3] = byte(dport)
	tcp[4] = byte(seq >> 24)
	tcp[5] = byte(seq >> 16)
	tcp[6] = byte(seq >> 8)
	tcp[7] = byte(seq)
	tcp[12] = 0x02 // SYN
	tcp[13] = 0
	tcp[14], tcp[15] = 0x02, 0x00 // window 512
	// Checksum TCP com pseudo-header.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8], pseudo[9] = 0, syscall.IPPROTO_TCP
	pseudo[10] = byte(tcpLen >> 8)
	pseudo[11] = byte(tcpLen)
	sum := checksum(append(pseudo, tcp...))
	tcp[16] = byte(sum >> 8)
	tcp[17] = byte(sum)
	return pkt
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func isSynAck(pkt []byte, dst net.IP, dport uint16) bool {
	// IP header: ihl = 4 bits baixos do byte 0.
	ihl := int(pkt[0]&0x0F) * 4
	if ihl+20 > len(pkt) {
		return false
	}
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return false
	}
	// Confere porta de destino e flag ACK+SYN (0x12).
	dportGot := uint16(tcp[2])<<8 | uint16(tcp[3])
	flags := tcp[13]
	return dportGot == dport && flags&0x12 == 0x12
}

func localIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IPv4(127, 0, 0, 1), nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

var _ = strconv.Itoa // keep import if unused in some build tags