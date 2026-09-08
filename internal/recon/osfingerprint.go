package recon

import (
	"fmt"
	"math"

	"github.com/nixteg/gofence/internal/assets"
	"gopkg.in/yaml.v3"
)

// OSFingerprint é uma assinatura de SO do banco embutido.
type OSFingerprint struct {
	Name   string `yaml:"name"`
	Device string `yaml:"device"`
	TTL    int    `yaml:"ttl"`
	Window int    `yaml:"window"`
	MSS    int    `yaml:"mss"`
}

type osFingerprintFile struct {
	Fingerprints []OSFingerprint `yaml:"fingerprints"`
}

var osFingerprintDB []OSFingerprint

func init() {
	loadOSFingerprintDB()
}

func loadOSFingerprintDB() {
	data, err := assets.OSFingerprints()
	if err != nil {
		return
	}
	var f osFingerprintFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return
	}
	osFingerprintDB = f.Fingerprints
}

// OSGuess contém os sinais observados e o melhor palpite.
type OSGuess struct {
	Name     string `json:"name"`
	Device   string `json:"device,omitempty"`
	Observed struct {
		TTL    int `json:"ttl"`
		Window int `json:"window"`
		MSS    int `json:"mss"`
	} `json:"observed"`
	Confidence float64 `json:"confidence"`
}

// GuessOS pontua cada assinatura do banco pela proximidade dos sinais
// observados (TTL, janela, MSS). Retorna o melhor candidato ou
// "desconhecido" quando nenhum chega perto o bastante.
func GuessOS(observedTTL, observedWindow, observedMSS int) OSGuess {
	best := OSGuess{Name: "desconhecido", Confidence: 0}
	for _, fp := range osFingerprintDB {
		score := 1.0
		// TTL: igual vale 1.0; divergência pequena (≤10) vale 0.8; senão 0.5.
		switch {
		case fp.TTL == observedTTL:
			score *= 1.0
		case abs(fp.TTL-observedTTL) <= 10:
			score *= 0.8
		default:
			score *= 0.5
		}
		// Janela e MSS: quanto mais perto, melhor (diferença relativa).
		score *= windowScore(fp.Window, observedWindow)
		score *= windowScore(fp.MSS, observedMSS)

		if score > best.Confidence {
			best = OSGuess{Name: fp.Name, Device: fp.Device, Confidence: score}
		}
	}
	best.Observed.TTL = observedTTL
	best.Observed.Window = observedWindow
	best.Observed.MSS = observedMSS
	if best.Name != "desconhecido" && best.Confidence < 0.4 {
		best = OSGuess{Name: "desconhecido", Confidence: best.Confidence}
		best.Observed.TTL = observedTTL
		best.Observed.Window = observedWindow
		best.Observed.MSS = observedMSS
	}
	return best
}

func windowScore(expected, observed int) float64 {
	if expected == 0 || observed == 0 {
		return 0.7
	}
	diff := math.Abs(float64(expected-observed)) / float64(expected)
	if diff <= 0.1 {
		return 1.0
	}
	if diff <= 0.3 {
		return 0.8
	}
	return 0.5
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (g OSGuess) String() string {
	if g.Name == "desconhecido" {
		return fmt.Sprintf("desconhecido (ttl=%d window=%d mss=%d)", g.Observed.TTL, g.Observed.Window, g.Observed.MSS)
	}
	return fmt.Sprintf("%s (%.0f%%)", g.Name, g.Confidence*100)
}