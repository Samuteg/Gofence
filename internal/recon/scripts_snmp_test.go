package recon

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// buildSnmpResponse monta uma resposta BER de GET com valor string no OID.
func buildSnmpResponse(version byte, value string) []byte {
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

	// varbind: SEQUENCE(OID, OCTET STRING(value))
	var vb []byte
	vb = append(vb, 0x06, byte(len(oid)))
	vb = append(vb, oid...)
	vb = append(vb, 0x04, byte(len(value)))
	vb = append(vb, value...)
	vb = append(vb, 0x30, byte(len(vb))) // wrap na varbind (content before wrapper)
	// A ordem acima gera OID+valor+tag; reconstruir corretamente:
	vb2 := []byte{0x06, byte(len(oid))}
	vb2 = append(vb2, oid...)
	vb2 = append(vb2, 0x04, byte(len(value)))
	vb2 = append(vb2, value...)
	varBind := append([]byte{0x30, byte(len(vb2))}, vb2...)

	// varbindlist
	varList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	// PDU GET-RESPONSE 0xA2
	pduContent := []byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	pduContent = append(pduContent, varList...)
	pdu := append([]byte{0xA2, byte(len(pduContent))}, pduContent...)

	// Message
	msgContent := []byte{0x02, 0x01, version}
	comm := []byte("public")
	msgContent = append(msgContent, 0x04, byte(len(comm)))
	msgContent = append(msgContent, comm...)
	msgContent = append(msgContent, pdu...)
	msg := append([]byte{0x30, byte(len(msgContent))}, msgContent...)
	return msg
}

func startFakeSNMP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// Detecta a versão pedida pelo client (v2c=1, v1=0) e responde.
			req := string(buf[:n])
			version := byte(1)
			if strings.Contains(req, "\x02\x01\x00") && !strings.Contains(req, "\x02\x01\x01") {
				version = 0
			}
			resp := buildSnmpResponse(version, "Cisco IOS 12.4 Router")
			pc.WriteTo(resp, addr)
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// @spec:AC-072 — checagem SNMP extrai a descrição do dispositivo
func TestSnmpSysDescr(t *testing.T) {
	port := startFakeSNMP(t)

	results := RunScripts("127.0.0.1", port, "snmp")
	found := false
	for _, r := range results {
		if r.Name == "sysdescr" && r.OK && strings.Contains(r.Detail, "Cisco") {
			found = true
		}
	}
	if !found {
		t.Errorf("AC-072: expected SNMP sysdescr to return device description, got %+v", results)
	}
}

var _ = fmt.Sprintf
var _ = time.Second