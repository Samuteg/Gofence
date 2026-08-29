package surface

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type TLSInfo struct {
	Host           string   `json:"host"`
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	CipherSuites   []string `json:"cipher_suites"`
	Protocols      []string `json:"protocols"`
	InsecureProtos []string `json:"insecure_protocols,omitempty"`
}

var insecureProtocols = map[string]bool{
	"SSLv3": true,
	"TLSv1.0": true,
	"TLSv1.1": true,
}

func AnalyzeTLS(host string, strict bool) (*TLSInfo, error) {
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         0x300, // SSLv3
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		Host:         host,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		CipherSuites: []string{},
		Protocols:    []string{},
	}

	hash := sha256.Sum256(cert.Raw)
	info.FingerprintSHA256 = hex.EncodeToString(hash[:])

	for _, cs := range cipherSuiteNames() {
		info.CipherSuites = append(info.CipherSuites, cs)
	}

	info.Protocols = []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
	for _, p := range info.Protocols {
		if insecureProtocols[p] {
			info.InsecureProtos = append(info.InsecureProtos, p)
		}
	}

	if strict && len(info.InsecureProtos) > 0 {
		fmt.Printf("WARNING: insecure protocols detected: %s\n", strings.Join(info.InsecureProtos, ", "))
	}

	return info, nil
}

func cipherSuiteNames() []string {
	names := []string{}
	for _, cs := range tls.CipherSuites() {
		names = append(names, cs.Name)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		names = append(names, cs.Name)
	}
	return names
}
