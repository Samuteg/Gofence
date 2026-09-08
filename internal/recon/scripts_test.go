package recon

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// @spec:AC-059 — script registrado roda para o serviço detectado
func TestRegisteredScriptRunsForService(t *testing.T) {
	RegisterScript("ssh", "test-probe", func(host string, port int) ScriptResult {
		return ScriptResult{Service: "ssh", Name: "test-probe", OK: true, Detail: "ran"}
	})

	results := RunScripts("127.0.0.1", 22, "ssh")
	found := false
	for _, r := range results {
		if r.Name == "test-probe" && r.OK && r.Detail == "ran" {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-059: expected registered script test-probe to run, got %+v", results)
	}
}

// @spec:AC-060 — checagem por protocolo executa e reporta (SMTP EHLO)
func TestProtocolCheckSMTPruns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("AC-060: listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprintf(c, "220 fake-smtp ESMTP\r\n")
				buf := make([]byte, 256)
				c.Read(buf) // EHLO
				fmt.Fprintf(c, "250-fake-smtp\r\n250 OK\r\n")
			}(conn)
		}
	}()

	results := RunScripts("127.0.0.1", port, "smtp")
	found := false
	for _, r := range results {
		if r.Name == "ehlo" && r.OK {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-060: expected smtp ehlo check to pass, got %+v", results)
	}
}