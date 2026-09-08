package surface

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"golang.org/x/time/rate"
)

type FuzzResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Header     string `json:"header,omitempty"`
	WAF        bool   `json:"waf,omitempty"`
	Wildcard   bool   `json:"wildcard,omitempty"`
}

type Fuzzer struct {
	client       *httpclient.Client
	Concurrency  int
	WAF          *ux.WAFDetector
	IgnoreStatus []int
	StatusCodes  []int
	ExcludeSize  []int64
	Retries      int
	Limiter      *rate.Limiter
	Progress     bool

	// Wildcard detection: requisição de referência com path aleatório.
	WildcardBase string // base URL usada para detectar página curinga
	wildcardHits int

	// Auth/personalização de requisição (SetAuth).
	auth      string
	authUser  string
	authPass  string
	cookie    string
	userAgent string
	bearer    string
	ntlmCreds string

	// ParamFuzz: quando setado, cada palavra vira valor deste parâmetro.
	ParamFuzz string

	// NTLM: token type3 calculado no primeiro uso (lazy) e reusado.
	ntlmOnce sync.Once
	ntlmToken string
}

func NewFuzzer(client *httpclient.Client, concurrency int) *Fuzzer {
	if concurrency <= 0 {
		concurrency = 50
	}
	return &Fuzzer{client: client, Concurrency: concurrency}
}

// countLines conta as linhas não-vazias de uma wordlist (para o total do progresso).
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n
}

func (f *Fuzzer) ignore(code int) bool {
	for _, s := range f.IgnoreStatus {
		if s == code {
			return true
		}
	}
	return false
}

func (f *Fuzzer) inStatusWhitelist(code int) bool {
	if len(f.StatusCodes) == 0 {
		return true
	}
	for _, s := range f.StatusCodes {
		if s == code {
			return true
		}
	}
	return false
}

func (f *Fuzzer) inExcludeSize(size int64) bool {
	for _, s := range f.ExcludeSize {
		if s == size {
			return true
		}
	}
	return false
}

// detectWildcard faz uma requisição de referência com path aleatório e guarda
// status+size. Respostas iguais à referência são descartadas (página curinga).
func (f *Fuzzer) detectWildcard(targetURL string) (int, int64, bool) {
	randomPath := fmt.Sprintf("gofence-wildcard-%d", rand.Intn(1<<30))
	reqURL := strings.ReplaceAll(targetURL, "FUZZ", randomPath)
	resp, err := f.client.HTTP.Get(reqURL)
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, int64(len(body)), true
}

func (f *Fuzzer) FuzzWeb(ctx context.Context, targetURL, wordlistPath, headerName, postData string) (<-chan FuzzResult, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}

	results := make(chan FuzzResult, 100)
	sem := make(chan struct{}, f.Concurrency)
	var wg sync.WaitGroup

	// Progresso opcional: conta palavras primeiro para o total.
	var progress *ux.Progress
	if f.Progress {
		total := countLines(wordlistPath)
		progress = ux.NewProgress(total, true)
	}

	go func() {
		defer file.Close()
		defer close(results)
		if progress != nil {
			defer progress.Done()
		}

		// Wildcard: descobre a referência antes da onda.
		wildcardStatus, wildcardSize, hasWildcard := 0, int64(0), false
		if f.WildcardBase != "" || strings.Contains(targetURL, "FUZZ") {
			wildcardStatus, wildcardSize, hasWildcard = f.detectWildcard(targetURL)
			if hasWildcard {
				fmt.Fprintf(os.Stderr, "wildcard detected: %d with size %d; matching responses will be discarded\n", wildcardStatus, wildcardSize)
			}
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// WAF wall: stop the wave and back off instead of hammering.
			if f.WAF != nil && f.WAF.Triggered() {
				fmt.Fprintf(os.Stderr, "WAF detected (%s): pausing fuzz wave\n", f.WAF.Signature())
				break
			}
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(word string) {
				defer wg.Done()
				defer func() { <-sem }()
				if progress != nil {
					progress.Inc()
				}

				if f.Limiter != nil {
					if err := f.Limiter.Wait(ctx); err != nil {
						return
					}
				}
				res := f.doFuzzWithRetry(targetURL, word, headerName, postData)
				if res == nil {
					return
				}
				if hasWildcard && res.StatusCode == wildcardStatus && res.Size == wildcardSize {
					res.Wildcard = true
				}
				results <- *res
			}(word)
		}
		wg.Wait()
	}()

	return results, nil
}

func (f *Fuzzer) doFuzzWithRetry(targetURL, word, headerName, postData string) *FuzzResult {
	attempts := f.Retries + 1
	for i := 0; i < attempts; i++ {
		res := f.doFuzz(targetURL, word, headerName, postData)
		if res != nil || i == attempts-1 {
			return res
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

func (f *Fuzzer) doFuzz(targetURL, word, headerName, postData string) *FuzzResult {
	reqURL := strings.ReplaceAll(targetURL, "FUZZ", word)

	// Param fuzzing: ?param=valor (preserva query string existente).
	if f.ParamFuzz != "" {
		sep := "?"
		if strings.Contains(reqURL, "?") {
			sep = "&"
		}
		reqURL += sep + f.ParamFuzz + "=" + word
	}

	method := "GET"
	var bodyReader io.Reader
	if postData != "" {
		method = "POST"
		body := strings.ReplaceAll(postData, "FUZZ", word)
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil
	}

	var fuzzHeaderVal string
	if headerName != "" {
		parts := strings.SplitN(headerName, ":", 2)
		if len(parts) == 2 {
			val := strings.ReplaceAll(strings.TrimSpace(parts[1]), "FUZZ", word)
			name := strings.TrimSpace(parts[0])
			if strings.EqualFold(name, "Host") {
				req.Host = val // Host não vai em Header: é o campo req.Host
			} else {
				req.Header.Set(name, val)
			}
			fuzzHeaderVal = name + ": " + val
		}
	}

	// Credenciais/cookies/UA configurados no fuzzer.
	if f.auth != "" {
		req.SetBasicAuth(f.authUser, f.authPass)
	}
	if f.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+f.bearer)
	}
	if f.ntlmCreds != "" {
		f.ntlmOnce.Do(func() {
			auth := newNTLM(f.ntlmCreds)
			auth.client = f.client.HTTP
			if tok, err := auth.handshake(reqURL); err == nil {
				f.ntlmToken = tok
			}
		})
		if f.ntlmToken != "" {
			req.Header.Set("Authorization", f.ntlmToken)
		}
	}
	if f.cookie != "" {
		req.Header.Set("Cookie", f.cookie)
	}
	if f.userAgent != "" {
		req.Header.Set("User-Agent", f.userAgent)
	}

	resp, err := f.client.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Whitelist de status: quando presente, só esses aparecem.
	if !f.inStatusWhitelist(resp.StatusCode) {
		return nil
	}
	if resp.StatusCode == 404 || f.ignore(resp.StatusCode) {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	size := int64(len(body))
	if f.inExcludeSize(size) {
		return nil
	}

	if f.WAF != nil {
		if detected, _ := f.WAF.Hit(resp.StatusCode, body); detected {
			return &FuzzResult{URL: reqURL, StatusCode: resp.StatusCode, Size: size, Header: fuzzHeaderVal, WAF: true}
		}
	}

	return &FuzzResult{
		URL:        reqURL,
		StatusCode: resp.StatusCode,
		Size:       size,
		Header:     fuzzHeaderVal,
	}
}