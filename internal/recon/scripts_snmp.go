package recon

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// SNMP GET sysDescr (1.3.6.1.2.1.1.1.0), comunidade "public".
// Tenta SNMPv2c primeiro; se não houver resposta, tenta SNMPv1 (fallback).

func init() {
	RegisterScript("snmp", "sysdescr", func(host string, port int) ScriptResult {
		desc, ok := snmpSysDescr(host, port, 2*time.Second)
		if !ok {
			return ScriptResult{Service: "snmp", Name: "sysdescr", OK: false, Detail: "no SNMP response"}
		}
		return ScriptResult{Service: "snmp", Name: "sysdescr", OK: true, Detail: truncate(desc)}
	})
}

func snmpSysDescr(host string, port int, timeout time.Duration) (string, bool) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	// v2c primeiro, v1 em fallback.
	for _, version := range []byte{1, 0} {
		desc, ok := snmpGet(addr, version, timeout)
		if ok {
			return desc, true
		}
	}
	return "", false
}

func snmpGet(addr string, version byte, timeout time.Duration) (string, bool) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildSnmpGet(version)
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", false
	}
	return parseSnmpSysDescr(buf[:n])
}

// buildSnmpGet monta um GET BER de sysDescr (1.3.6.1.2.1.1.1.0).
func buildSnmpGet(version byte) []byte {
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0

	var reqID []byte
	reqID = append(reqID, 0x02, 0x01, 0x01) // INTEGER 1

	// VarBind: (OID, NULL)
	var vbContent []byte
	vbContent = append(vbContent, 0x06, byte(len(oid)))
	vbContent = append(vbContent, oid...)
	vbContent = append(vbContent, 0x05, 0x00) // NULL

	var vbl []byte
	vbl = append(vbl, 0x30, byte(len(vbContent)))
	vbl = append(vbl, vbContent...)

	// PDU: GET (0xA0) { request-id, error-status, error-index, varbindlist }
	var pduContent []byte
	pduContent = append(pduContent, reqID...)
	pduContent = append(pduContent, 0x02, 0x01, 0x00) // error-status 0
	pduContent = append(pduContent, 0x02, 0x01, 0x00) // error-index 0
	pduContent = append(pduContent, vbl...)

	var pdu []byte
	pdu = append(pdu, 0xA0, byte(len(pduContent)))
	pdu = append(pdu, pduContent...)

	// Message: SEQUENCE { version, community, pdu }
	var msgContent []byte
	msgContent = append(msgContent, 0x02, 0x01, version) // INTEGER version
	community := []byte("public")
	msgContent = append(msgContent, 0x04, byte(len(community)))
	msgContent = append(msgContent, community...)
	msgContent = append(msgContent, pdu...)

	msg := []byte{0x30, byte(len(msgContent))}
	msg = append(msg, msgContent...)
	return msg
}

// parseSnmpSysDescr extrai o valor string do OID sysDescr na resposta BER.
func parseSnmpSysDescr(data []byte) (string, bool) {
	// Estrutura: SEQUENCE > SEQUENCE > (version, community, PDU > varbindlist
	// > varbind > SEQUENCE(OID, value)). Faz uma varredura linear em busca de
	// uma string (0x04) de tamanho razoável que não seja a comunidade.
	if len(data) < 2 || data[0] != 0x30 {
		return "", false
	}
	// Pula a SEQUENCE externa (2 bytes de header) e procura o primeiro OCTET
	// STRING com conteúdo após o OID.
	body := data[2:]
	for i := 0; i+1 < len(body); i++ {
		if body[i] == 0x04 && i+2 < len(body) {
			l := int(body[i+1])
			if l > 0 && i+2+l <= len(body) {
				val := string(body[i+2 : i+2+l])
				if val != "public" && !strings.ContainsAny(val, "\x00") {
					return val, true
				}
			}
		}
	}
	return "", false
}

var _ = binary.BigEndian // reservado para extensões futuras do parser