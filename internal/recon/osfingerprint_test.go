package recon

import (
	"testing"
)

// @spec:AC-055 — fingerprint TCP produz palpite de SO
func TestGuessOSFromTCPSignals(t *testing.T) {
	// Sinais típicos de Linux (ttl=64, window=64240, mss=1460).
	guess := GuessOS(64, 64240, 1460)
	if guess.Name == "desconhecido" || guess.Name != "Linux" {
		t.Errorf("AC-055: expected Linux guess for (64,64240,1460), got %q", guess.Name)
	}
	if guess.Confidence <= 0.4 {
		t.Errorf("AC-055: expected confidence > 0.4, got %.2f", guess.Confidence)
	}
}

// @spec:AC-055 — fingerprint sem correspondência retorna desconhecido
func TestGuessOSUnknownWhenNoMatch(t *testing.T) {
	guess := GuessOS(1, 1, 1)
	if guess.Name != "desconhecido" {
		t.Errorf("AC-055: expected desconhecido for garbage signals, got %q", guess.Name)
	}
}