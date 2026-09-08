package recon

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// SMB2 negotiate (não-destrutivo): envia o request mínimo e lê a resposta
// para extrair o dialect negociado (2.0.2 / 2.1 / 3.0 / 3.1.1).

func init() {
	// 445 é "microsoft-ds" no mapa estático; registra nos dois nomes.
	for _, svc := range []string{"microsoft-ds", "smb", "netbios-ssn"} {
		RegisterScript(svc, "negotiate", func(host string, port int) ScriptResult {
			dialect, ok := smbNegotiate(host, port, 2*time.Second)
			if !ok {
				return ScriptResult{Service: svc, Name: "negotiate", OK: false, Detail: "no SMB negotiate response"}
			}
			return ScriptResult{Service: svc, Name: "negotiate", OK: true, Detail: "SMB " + dialect}
		})
	}
}

func smbNegotiate(host string, port int, timeout time.Duration) (string, bool) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildSMB2Negotiate()); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 64 {
		return "", false
	}
	return parseSMB2Dialect(buf[:n])
}

// buildSMB2Negotiate monta NetBIOS session header + SMB2 NEGOTIATE.
func buildSMB2Negotiate() []byte {
	// SMB2 header (64 bytes).
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // StructureSize
	// Command: 0x0000 = NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[8:10], 0) // CreditRequest
	binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001) // MessageId
	// Flags 0, NextCommand 0, ProcessId 0
	// TreeId 0, SessionId 0, Signature 16 bytes zeros

	// Body: StructureSize (36) + DialectCount (1) + SecurityMode + Reserved
	// + Capabilities + ClientGuid + NegotiateContextOffset/Count/Reserved.
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 1)  // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 1)  // SecurityMode: SIGNING_ENABLED
	// Capabilities: 0x00000001 (DFS)
	binary.LittleEndian.PutUint32(body[8:12], 0x00000001)
	// ClientGuid: 16 bytes aleatórios determinísticos (zeros são aceitos)
	// Dialects: [0x0202] (SMB 2.0.2) — anuncia compatibilidade
	dialects := []byte{0x02, 0x02}
	dialects = append(dialects, 0x03, 0x00) // SMB 3.0

	// Payload = header + body + dialects.
	payload := append(hdr, body...)
	payload = append(payload, dialects...)

	// NetBIOS session header: 0x00 + 3-byte big-endian length.
	nb := make([]byte, 4)
	nb[0] = 0x00
	l := len(payload)
	nb[1] = byte(l >> 16)
	nb[2] = byte(l >> 8)
	nb[3] = byte(l)
	return append(nb, payload...)
}

// parseSMB2Dialect extrai o dialect da resposta SMB2 negotiate.
// Resposta: NetBIOS header (4) + SMB2 header (64) + body com DialectRevision
// (offset 2 no body, 2 bytes little-endian).
func parseSMB2Dialect(data []byte) (string, bool) {
	// data inclui o NetBIOS header (4 bytes).
	if len(data) < 4+64+4 {
		return "", false
	}
	if data[4] != 0xFE || data[5] != 'S' || data[6] != 'M' || data[7] != 'B' {
		return "", false
	}
	// Command no header SMB2 (offset 8 no header = data[4+8]).
	cmd := binary.LittleEndian.Uint16(data[12:14])
	if cmd != 0x0000 { // NEGOTIATE response
		return "", false
	}
	// Body começa em 4+64; DialectRevision em body+2.
	body := data[4+64:]
	if len(body) < 4 {
		return "", false
	}
	dialect := binary.LittleEndian.Uint16(body[2:4])
	switch dialect {
	case 0x0202:
		return "2.0.2", true
	case 0x0210:
		return "2.1", true
	case 0x0300:
		return "3.0", true
	case 0x0302:
		return "3.0.2", true
	case 0x0311:
		return "3.1.1", true
	default:
		return fmt.Sprintf("0x%04x", dialect), true
	}
}