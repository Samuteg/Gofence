package surface

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// Campos de autenticação/personalização de requisição.
type FuzzAuth struct {
	User     string
	Pass     string
	Cookie   string
	UserAgent string
}

func (f *Fuzzer) SetAuth(auth FuzzAuth) {
	f.auth = "basic"
	f.authUser = auth.User
	f.authPass = auth.Pass
	f.cookie = auth.Cookie
	f.userAgent = auth.UserAgent
}

// ExtendFuzz gera as variantes de cada palavra com as extensões dadas
// (ex.: -x php,html → index.php, index.html) e roda o fuzz sobre todas.
func (f *Fuzzer) ExtendWordlist(wordlistPath string, extensions []string) (string, error) {
	if len(extensions) == 0 {
		return wordlistPath, nil
	}
	in, err := os.Open(wordlistPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "gofence-ext-*.txt")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		for _, ext := range extensions {
			ext = strings.TrimPrefix(ext, ".")
			if !strings.HasSuffix(word, "."+ext) {
				fmt.Fprintf(tmp, "%s.%s\n", word, ext)
			}
		}
	}
	return tmp.Name(), scanner.Err()
}

// RecursiveResult agrega o fuzz recursivo: achados de todos os níveis.
type RecursiveResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Depth      int    `json:"depth"`
}

// FuzzRecursive executa o fuzz BFS com profundidade limitada: diretórios
// descobertos (status 2xx/301 + path terminando em /) viram novos alvos.
func (f *Fuzzer) FuzzRecursive(ctx context.Context, baseURL, wordlistPath string, depth int) ([]RecursiveResult, error) {
	visited := map[string]bool{}
	var all []RecursiveResult
	mu := sync.Mutex{}

	queue := []string{ensureFuzzSlot(baseURL)}
	for d := 0; d < depth && len(queue) > 0; d++ {
		var next []string
		for _, base := range queue {
			if visited[base] {
				continue
			}
			visited[base] = true

			results, err := f.FuzzWeb(ctx, base, wordlistPath, "", "")
			if err != nil {
				return all, err
			}
			for r := range results {
				if r.WAF || r.Wildcard {
					continue
				}
				mu.Lock()
				all = append(all, RecursiveResult{URL: r.URL, StatusCode: r.StatusCode, Size: r.Size, Depth: d})
				mu.Unlock()
				if isDirResult(r) {
					next = append(next, ensureFuzzSlot(ensureTrailingSlash(r.URL)))
				}
			}
		}
		queue = next
	}
	return all, nil
}

// ensureFuzzSlot garante que a base URL tenha o marcador FUZZ para o fuzz.
func ensureFuzzSlot(u string) string {
	if strings.Contains(u, "FUZZ") {
		return u
	}
	if strings.HasSuffix(u, "/") {
		return u + "FUZZ"
	}
	return u + "/FUZZ"
}

func isDirResult(r FuzzResult) bool {
	return (r.StatusCode == 200 || r.StatusCode == 301 || r.StatusCode == 302) && strings.HasSuffix(r.URL, "/")
}

func ensureTrailingSlash(u string) string {
	if strings.HasSuffix(u, "/") {
		return u
	}
	return u + "/"
}

// FuzzVhost fuzza vhosts via Host header, filtrando respostas idênticas à base.
func (f *Fuzzer) FuzzVhost(ctx context.Context, targetBase, wordlistPath string) ([]FuzzResult, error) {
	// Referência: resposta sem Host customizado.
	refStatus, refSize, _ := f.detectWildcard(targetBase)

	results, err := f.FuzzWeb(ctx, targetBase, wordlistPath, "Host: FUZZ", "")
	if err != nil {
		return nil, err
	}
	var out []FuzzResult
	for r := range results {
		if r.WAF || r.Wildcard {
			continue
		}
		// Filtra respostas iguais à base (vhost inexistente cai no default).
		if refStatus == r.StatusCode && refSize == r.Size {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// RobotsPaths extrai paths de robots.txt (Disallow:/Allow:).
func RobotsPaths(client *httpclient.Client, baseURL string) []string {
	resp, err := client.HTTP.Get(strings.TrimRight(baseURL, "/") + "/robots.txt")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var paths []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"Disallow:", "Allow:"} {
			if strings.HasPrefix(line, prefix) {
				p := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if p != "" && !strings.HasPrefix(p, "*") {
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}

// SitemapPaths extrai URLs de sitemap.xml (tags <loc>).
func SitemapPaths(client *httpclient.Client, baseURL string) []string {
	resp, err := client.HTTP.Get(strings.TrimRight(baseURL, "/") + "/sitemap.xml")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var paths []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<loc>") && strings.HasSuffix(line, "</loc>") {
			p := strings.TrimSuffix(strings.TrimPrefix(line, "<loc>"), "</loc>")
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

// SeedWordlist cria uma wordlist temporária a partir de paths de robots/sitemap.
func SeedWordlist(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("no paths found")
	}
	tmp, err := os.CreateTemp("", "gofence-seed-*.txt")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	for _, p := range paths {
		fmt.Fprintln(tmp, strings.TrimLeft(p, "/"))
	}
	return tmp.Name(), nil
}

// ---- Resume ----

// FuzzState é o estado serializável de uma sessão de fuzz.
type FuzzState struct {
	TargetURL  string      `json:"target_url"`
	Wordlist   string      `json:"wordlist"`
	Processed  int         `json:"processed"`
	Findings   []FuzzResult `json:"findings"`
	Done       bool        `json:"done"`
}

// SaveState grava o estado atual da sessão.
func (f *Fuzzer) SaveState(path string, state FuzzState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadState lê o estado salvo (resume).
func LoadState(path string) (*FuzzState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st FuzzState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// FuzzResume continua uma sessão: pula as palavras já processadas e anexa
// os achados anteriores aos novos.
func (f *Fuzzer) FuzzResume(ctx context.Context, state FuzzState) ([]FuzzResult, error) {
	// Pula as primeiras `Processed` palavras da wordlist.
	file, err := os.Open(state.Wordlist)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	results := make(chan FuzzResult, 100)
	sem := make(chan struct{}, f.Concurrency)
	var wg sync.WaitGroup
	index := 0
	go func() {
		defer close(results)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}
			if index < state.Processed {
				index++
				continue
			}
			index++
			wg.Add(1)
			sem <- struct{}{}
			go func(w string) {
				defer wg.Done()
				defer func() { <-sem }()
				if res := f.doFuzzWithRetry(state.TargetURL, w, "", ""); res != nil {
					results <- *res
				}
			}(word)
		}
		wg.Wait()
	}()

	var out []FuzzResult
	out = append(out, state.Findings...)
	for r := range results {
		out = append(out, r)
	}
	return out, nil
}

var _ = http.MethodGet
var _ = filepath.Join