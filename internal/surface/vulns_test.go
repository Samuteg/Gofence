package surface

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// @spec:AC-015 — execução de template
func TestRunTemplateMatch(t *testing.T) {
	tmplContent := `
id: test-template
name: Test Template
requests:
  - method: GET
    path: /admin
matchers:
  - type: status
    status: 200
`
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	tmpl, err := LoadTemplate(tmplPath)
	if err != nil {
		t.Fatalf("AC-015: failed to load template: %v", err)
	}
	if tmpl.ID != "test-template" {
		t.Errorf("AC-015: expected template ID 'test-template', got %q", tmpl.ID)
	}
}

// @spec:AC-016 — execução em lote
func TestLoadTemplateDir(t *testing.T) {
	dir := t.TempDir()
	tmpl1 := `id: t1
name: T1
requests:
  - method: GET
    path: /`
	tmpl2 := `id: t2
name: T2
requests:
  - method: GET
    path: /admin`
	os.WriteFile(filepath.Join(dir, "t1.yaml"), []byte(tmpl1), 0644)
	os.WriteFile(filepath.Join(dir, "t2.yaml"), []byte(tmpl2), 0644)
	os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("not yaml"), 0644)

	templates, err := LoadTemplateDir(dir)
	if err != nil {
		t.Fatalf("AC-016: failed to load dir: %v", err)
	}
	if len(templates) != 2 {
		t.Errorf("AC-016: expected 2 templates, got %d", len(templates))
	}
}

// @spec:AC-015 — matcher logic
func TestMatcherLogic(t *testing.T) {
	engine := NewVulnEngine(httpclient.NewFromEnv())
	m := VulnMatcher{Type: "status", Status: 200}
	if !engine.match(m, 200, "", "") {
		t.Errorf("AC-015: status matcher should match 200")
	}
	if engine.match(m, 404, "", "") {
		t.Errorf("AC-015: status matcher should not match 404")
	}
}
