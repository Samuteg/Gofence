package recon

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// buildSMB2NegotiateResponse monta uma resposta SMB2 negotiate com dialect
// 3.1.1 (0x0311), com NetBIOS session header.
func buildSMB2NegotiateResponse() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // StructureSize
	// Command: NEGOTIATE = 0
	// Status: 0
	binary.LittleEndian.PutUint32(hdr[8:12], 0) // CreditRequest/Response
	binary.LittleEndian.PutUint32(hdr[16:20], 1)
	// Flags, NextCommand, ProcessId, TreeId, SessionId, Signature = zeros

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 64) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x0311) // DialectRevision = 3.1.1

	payload := append(hdr, body...)
	nb := make([]byte, 4)
	nb[0] = 0x00
	l := len(payload)
	nb[1] = byte(l >> 16)
	nb[2] = byte(l >> 8)
	nb[3] = byte(l)
	return append(nb, payload...)
}

func startFakeSMB(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 512)
				c.Read(buf) // request (ignorado)
				c.Write(buildSMB2NegotiateResponse())
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().(*net.TCPAddr).Port
}

// @spec:AC-073 — checagem SMB reporta o dialect negociado
func TestSMBNegotiateDialect(t *testing.T) {
	port := startFakeSMB(t)

	results := RunScripts("127.0.0.1", port, "microsoft-ds")
	found := false
	for _, r := range results {
		if r.Name == "negotiate" && r.OK && strings.Contains(r.Detail, "3.1.1") {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-073: expected SMB negotiate dialect 3.1.1, got %+v", results)
	}
}

var _ = fmt.Sprintf