package assets

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed wordlists/*.txt templates/*.yaml
var embedded embed.FS

// Wordlist returns the lines of an embedded wordlist (subdomains.txt / paths.txt).
func Wordlist(name string) ([]string, error) {
	data, err := embedded.ReadFile("wordlists/" + name)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

// TemplatesFS exposes the embedded template directory for LoadTemplateDir.
func TemplatesFS() fs.FS {
	sub, _ := fs.Sub(embedded, "templates")
	return sub
}

// HasWordlist reports whether an embedded wordlist exists.
func HasWordlist(name string) bool {
	_, err := embedded.ReadFile("wordlists/" + name)
	return err == nil
}
