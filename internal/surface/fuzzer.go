package surface

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/nixteg/gofence/pkg/httpclient"
)

type FuzzResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Header     string `json:"header,omitempty"`
}

type Fuzzer struct {
	client      *httpclient.Client
	Concurrency int
}

func NewFuzzer(client *httpclient.Client, concurrency int) *Fuzzer {
	if concurrency <= 0 {
		concurrency = 50
	}
	return &Fuzzer{client: client, Concurrency: concurrency}
}

func (f *Fuzzer) FuzzWeb(targetURL, wordlistPath, headerName, postData string) (<-chan FuzzResult, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}

	results := make(chan FuzzResult, 100)
	sem := make(chan struct{}, f.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer file.Close()
		defer close(results)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(word string) {
				defer wg.Done()
				defer func() { <-sem }()

				res := f.doFuzz(targetURL, word, headerName, postData)
				if res != nil {
					results <- *res
				}
			}(word)
		}
		wg.Wait()
	}()

	return results, nil
}

func (f *Fuzzer) doFuzz(targetURL, word, headerName, postData string) *FuzzResult {
	reqURL := strings.ReplaceAll(targetURL, "FUZZ", word)

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

	if headerName != "" {
		parts := strings.SplitN(headerName, ":", 2)
		if len(parts) == 2 {
			val := strings.ReplaceAll(strings.TrimSpace(parts[1]), "FUZZ", word)
			req.Header.Set(strings.TrimSpace(parts[0]), val)
		}
	}

	resp, err := f.client.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return &FuzzResult{
		URL:        reqURL,
		StatusCode: resp.StatusCode,
		Size:       int64(len(body)),
	}
}
