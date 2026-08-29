package surface

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nixteg/gofence/pkg/httpclient"
	"gopkg.in/yaml.v3"
)

type VulnTemplate struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Requests []struct {
		Method  string            `yaml:"method"`
		Path    string            `yaml:"path"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	} `yaml:"requests"`
	Matchers []struct {
		Type   string `yaml:"type"`
		Part   string `yaml:"part"`
		Regex  string `yaml:"regex"`
		Status int    `yaml:"status"`
		Words  string `yaml:"words"`
	} `yaml:"matchers"`
}

type VulnResult struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Matched    bool   `json:"matched"`
	Details    string `json:"details,omitempty"`
}

type VulnEngine struct {
	client *httpclient.Client
}

func NewVulnEngine(client *httpclient.Client) *VulnEngine {
	return &VulnEngine{client: client}
}

func (e *VulnEngine) RunTemplate(tmpl *VulnTemplate, target string) *VulnResult {
	result := &VulnResult{TemplateID: tmpl.ID, Name: tmpl.Name}

	for _, req := range tmpl.Requests {
		url := target + req.Path
		var bodyReader io.Reader
		if req.Body != "" {
			bodyReader = strings.NewReader(req.Body)
		}

		httpReq, err := http.NewRequest(req.Method, url, bodyReader)
		if err != nil {
			continue
		}
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}

		resp, err := e.client.HTTP.Do(httpReq)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		for _, m := range tmpl.Matchers {
			if e.match(m, resp.StatusCode, string(respBody)) {
				result.Matched = true
				result.Details = fmt.Sprintf("matched %s (status=%d)", m.Type, resp.StatusCode)
				return result
			}
		}
	}
	return result
}

func (e *VulnEngine) match(matcher struct {
	Type   string `yaml:"type"`
	Part   string `yaml:"part"`
	Regex  string `yaml:"regex"`
	Status int    `yaml:"status"`
	Words  string `yaml:"words"`
}, statusCode int, body string) bool {
	switch matcher.Type {
	case "status":
		return matcher.Status == statusCode
	case "regex":
		re, err := regexp.Compile(matcher.Regex)
		if err != nil {
			return false
		}
		return re.MatchString(body)
	case "word":
		return strings.Contains(body, matcher.Words)
	}
	return false
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
