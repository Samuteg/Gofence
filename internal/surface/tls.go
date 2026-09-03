package surface

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

type CipherGrade struct {
	Name  string `json:"name"`
	Grade string `json:"grade"` // A (strong) / B (CBC) / C (weak/obsolete)
	Weak  bool   `json:"weak"`
}

type TLSInfo struct {
	Host              string        `json:"host"`
	Subject           string        `json:"subject"`
	Issuer            string        `json:"issuer"`
	NotBefore         string        `json:"not_before"`
	NotAfter          string        `json:"not_after"`
	FingerprintSHA256 string        `json:"fingerprint_sha256"`
	CipherSuites      []string      `json:"cipher_suites"`
	CipherGrades      []CipherGrade `json:"cipher_grades"`
	Protocols         []string      `json:"protocols"`
	InsecureProtos    []string      `json:"insecure_protocols,omitempty"`
	Grade             string        `json:"grade"`
}

var insecureProtocols = map[string]bool{
	"SSLv3":   true,
	"TLSv1.0": true,
	"TLSv1.1": true,
}

// AnalyzeTLS negotiates with a TLS1.2+ client by default and grades every known
// cipher suite (A/B/C) so obsolete ones (RC4/3DES/TLS1.0/1.1) are never reported
// as equal to strong ciphers. With strict=true it also probes for legacy
// protocol support and warns when the server negotiates below TLS1.2.
func AnalyzeTLS(host string, strict bool) (*TLSInfo, error) {
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
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
		Protocols:    []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
	}

	hash := sha256.Sum256(cert.Raw)
	info.FingerprintSHA256 = hex.EncodeToString(hash[:])

	for _, cs := range tls.CipherSuites() {
		info.CipherSuites = append(info.CipherSuites, cs.Name)
		info.CipherGrades = append(info.CipherGrades, gradeCipher(cs))
	}
	for _, cs := range tls.InsecureCipherSuites() {
		info.CipherSuites = append(info.CipherSuites, cs.Name)
		info.CipherGrades = append(info.CipherGrades, gradeCipher(cs))
	}

	if strict {
		if neg := negotiatedVersion(host); neg != "" && insecureProtocols[neg] {
			info.InsecureProtos = append(info.InsecureProtos, neg)
			fmt.Fprintf(os.Stderr, "WARNING: server negotiated insecure protocol %s\n", neg)
		}
	}

	info.Grade = overallGrade(info.CipherGrades, info.InsecureProtos)
	return info, nil
}

func gradeCipher(cs *tls.CipherSuite) CipherGrade {
	weak := false
	for _, w := range tls.InsecureCipherSuites() {
		if w.ID == cs.ID {
			weak = true
		}
	}
	name := cs.Name
	grade := "A"
	switch {
	case weak || strings.Contains(name, "RC4") || strings.Contains(name, "3DES") ||
		strings.Contains(name, "DES") || strings.Contains(name, "EXP") ||
		strings.Contains(name, "NULL") || strings.Contains(name, "anon"):
		grade = "C"
	case strings.Contains(name, "CBC"):
		grade = "B"
	}
	return CipherGrade{Name: name, Grade: grade, Weak: weak}
}

func overallGrade(grades []CipherGrade, insecureProtos []string) string {
	if len(insecureProtos) > 0 {
		return "C"
	}
	grade := "A"
	for _, g := range grades {
		if g.Grade == "C" {
			return "C"
		}
		if g.Grade == "B" {
			grade = "B"
		}
	}
	return grade
}

func negotiatedVersion(host string) string {
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         0x300, // SSLv3, accept anything the server offers
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()
	switch conn.ConnectionState().Version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return ""
}
