package ux

import (
	"hash/fnv"
	"strings"
)

// wafMarkers are substrings that identify a WAF/interstitial response body.
var wafMarkers = []string{
	"vercel security checkpoint",
	"cloudflare",
	"attention required! | cloudflare",
	"access denied",
	"you are being rate limited",
	"security checkpoint",
	"request blocked",
}

// WAFDetector flags WAF walls so callers can stop the wave and back off instead
// of letting 403 checkpoint pages pollute the output as "results".
type WAFDetector struct {
	seen      map[uint64]int
	threshold int
	triggered bool
	signature string
}

func NewWAFDetector(threshold int) *WAFDetector {
	if threshold <= 0 {
		threshold = 3
	}
	return &WAFDetector{seen: make(map[uint64]int), threshold: threshold}
}

// Hit inspects a response; it returns true (and the matched signature) once a
// WAF is identified, after which Triggered stays true.
func (w *WAFDetector) Hit(status int, body []byte) (bool, string) {
	if w.triggered {
		return true, w.signature
	}
	lower := strings.ToLower(string(body))
	for _, m := range wafMarkers {
		if strings.Contains(lower, m) {
			w.triggered = true
			w.signature = m
			return true, m
		}
	}
	// A large body served repeatedly is the classic "stable checkpoint page".
	if len(body) > 1024 {
		h := fnv.New64a()
		h.Write(body)
		key := h.Sum64()
		w.seen[key]++
		if w.seen[key] >= w.threshold {
			w.triggered = true
			w.signature = "repeated checkpoint body"
			return true, w.signature
		}
	}
	return false, ""
}

func (w *WAFDetector) Triggered() bool   { return w.triggered }
func (w *WAFDetector) Signature() string { return w.signature }
