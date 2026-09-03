package ux

import "testing"

func TestWAFDetector(t *testing.T) {
	d := NewWAFDetector(0)
	if d.Triggered() {
		t.Fatal("fresh detector should not be triggered")
	}
	// Explicit marker body.
	if ok, sig := d.Hit(403, []byte("<title>Vercel Security Checkpoint</title>")); !ok {
		t.Fatalf("expected WAF hit on vercel marker, got sig=%q", sig)
	}
	if !d.Triggered() || d.Signature() == "" {
		t.Fatal("detector should stay triggered with a signature")
	}
}

func TestWAFDetectorRepeatedBody(t *testing.T) {
	d := NewWAFDetector(3)
	body := make([]byte, 2000)
	for i := range body {
		body[i] = 'x'
	}
	// Below threshold: not triggered yet.
	if ok, _ := d.Hit(403, body); ok {
		t.Fatal("should not trigger before threshold")
	}
	d.Hit(403, body)
	d.Hit(403, body)
	if ok, _ := d.Hit(403, body); !ok {
		t.Fatal("should trigger after repeated large checkpoint body")
	}
}

func TestWAFDetectorClean(t *testing.T) {
	d := NewWAFDetector(0)
	if ok, _ := d.Hit(200, []byte("welcome to our site")); ok {
		t.Fatal("clean 200 body must not trigger WAF")
	}
}
