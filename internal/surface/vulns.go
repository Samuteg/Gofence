package surface

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nixteg/gofence/pkg/httpclient"
	"gopkg.in/yaml.v3"
)

type VulnRequest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type VulnMatcher struct {
	Type   string `yaml:"type"`
	Part   string `yaml:"part"`
	Regex  string `yaml:"regex"`
	Status int    `yaml:"status"`
	Words  string `yaml:"words"`
}

type VulnExtractor struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"` // regex | kv | word
	Part  string `yaml:"part"` // body | header
	Regex string `yaml:"regex"`
	Group int    `yaml:"group"`
	Key   string `yaml:"key"` // for kv
}

type VulnTemplate struct {
	ID         string          `yaml:"id"`
	Name       string          `yaml:"name"`
	Requests   []VulnRequest   `yaml:"requests"`
	Extractors []VulnExtractor `yaml:"extractors"`
	Matchers   []VulnMatcher   `yaml:"matchers"`
}

type VulnResult struct {
	TemplateID string            `json:"template_id"`
	Name       string            `json:"name"`
	Executed   int               `json:"executed"`
	Failed     int               `json:"failed"`
	Matched    bool              `json:"matched"`
	Details    string            `json:"details,omitempty"`
	Extracted  map[string]string `json:"extracted,omitempty"`
}

type VulnEngine struct {
	client *httpclient.Client
}

func NewVulnEngine(client *httpclient.Client) *VulnEngine {
	return &VulnEngine{client: client}
}

// RunTemplate executes every request in the template (chained: extractors feed
// later requests via {{var}}), applies matchers, and records how many requests
// ran/failed so silent non-matches are still visible in the summary.
func (e *VulnEngine) RunTemplate(tmpl *VulnTemplate, target string) *VulnResult {
	result := &VulnResult{
		TemplateID: tmpl.ID,
		Name:       tmpl.Name,
		Executed:   len(tmpl.Requests),
		Extracted:  map[string]string{},
	}

	for i, req := range tmpl.Requests {
		url := interpolate(target+req.Path, result.Extracted)
		var bodyReader io.Reader
		if req.Body != "" {
			bodyReader = strings.NewReader(interpolate(req.Body, result.Extracted))
		}

		httpReq, err := http.NewRequest(req.Method, url, bodyReader)
		if err != nil {
			result.Failed++
			continue
		}
		for k, v := range req.Headers {
			httpReq.Header.Set(k, interpolate(v, result.Extracted))
		}

		resp, err := e.client.HTTP.Do(httpReq)
		if err != nil {
			result.Failed++
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var hdr strings.Builder
		for k, v := range resp.Header {
			hdr.WriteString(k + ": " + strings.Join(v, ", ") + "\n")
		}

		for _, ex := range tmpl.Extractors {
			e.extract(ex, string(respBody), hdr.String(), result.Extracted)
		}

		for _, m := range tmpl.Matchers {
			if e.match(m, resp.StatusCode, string(respBody), hdr.String()) {
				result.Matched = true
				result.Details = fmt.Sprintf("matched %s on request %d (status=%d)", m.Type, i+1, resp.StatusCode)
				return result
			}
		}
	}
	return result
}

func (e *VulnEngine) match(m VulnMatcher, statusCode int, body, header string) bool {
	part := body
	if m.Part == "header" {
		part = header
	}
	switch m.Type {
	case "status":
		return m.Status == statusCode
	case "regex":
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return false
		}
		return re.MatchString(part)
	case "word":
		return strings.Contains(part, m.Words)
	}
	return false
}

func (e *VulnEngine) extract(ex VulnExtractor, body, header string, vars map[string]string) {
	if ex.Name == "" {
		return
	}
	part := body
	if ex.Part == "header" {
		part = header
	}
	switch ex.Type {
	case "regex":
		re, err := regexp.Compile(ex.Regex)
		if err != nil {
			return
		}
		groups := re.FindStringSubmatch(part)
		g := ex.Group
		if g < 1 || g >= len(groups) {
			g = 0
		}
		if len(groups) > g {
			vars[ex.Name] = groups[g]
		}
	case "word":
		if strings.Contains(part, ex.Regex) {
			vars[ex.Name] = ex.Regex
		}
	case "kv":
		re, err := regexp.Compile(ex.Key + `;*\s*([^\n\r]+)`)
		if err != nil {
			return
		}
		if groups := re.FindStringSubmatch(part); len(groups) > 1 {
			vars[ex.Name] = strings.TrimSpace(groups[1])
		}
	}
}

func interpolate(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func LoadTemplate(path string) (*VulnTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tmpl VulnTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

func LoadTemplateDir(dir string) ([]*VulnTemplate, error) {
	var templates []*VulnTemplate
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		tmpl, err := LoadTemplate(path)
		if err != nil {
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// LoadTemplateFS loads templates from an fs.FS (e.g. embedded assets).
func LoadTemplateFS(fsys fs.FS) ([]*VulnTemplate, error) {
	var templates []*VulnTemplate
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil
		}
		var tmpl VulnTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil
		}
		templates = append(templates, &tmpl)
		return nil
	})
	return templates, err
}
