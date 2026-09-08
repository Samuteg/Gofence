package surface

import (
	"fmt"
	"io"
	"net/http"

	"github.com/nixteg/gofence/pkg/httpclient"
)

// S3Result é o resultado de um teste de bucket S3.
type S3Result struct {
	Bucket     string `json:"bucket"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Exists     bool   `json:"exists"`
	Private    bool   `json:"private,omitempty"`
}

// mapS3Status isola o mapeamento status→resultado (testável sem rede).
// 200/301/403 = existe (403 é privado); 404/outros = não existe.
func mapS3Status(code int) S3Result {
	switch code {
	case http.StatusOK, http.StatusMovedPermanently, http.StatusTemporaryRedirect:
		return S3Result{StatusCode: code, Exists: true}
	case http.StatusForbidden:
		return S3Result{StatusCode: code, Exists: true, Private: true}
	default:
		return S3Result{StatusCode: code, Exists: false}
	}
}

// CheckS3Bucket testa https://<bucket>.s3.amazonaws.com. 200/301 = público;
// 403 = existe mas privado; 404 = não existe. Erros de transporte = não existe.
func CheckS3Bucket(client *httpclient.Client, bucket string) S3Result {
	url := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
	resp, err := client.HTTP.Get(url)
	if err != nil {
		return S3Result{Bucket: bucket, URL: url, Exists: false}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // esgota a conexão

	res := mapS3Status(resp.StatusCode)
	res.Bucket = bucket
	res.URL = url
	return res
}

// FuzzS3 testa cada nome da wordlist como bucket S3, com concorrência.
func (f *Fuzzer) FuzzS3(bucketNames []string) []S3Result {
	results := make(chan S3Result, len(bucketNames))
	sem := make(chan struct{}, f.Concurrency)
	for _, name := range bucketNames {
		sem <- struct{}{}
		go func(n string) {
			defer func() { <-sem }()
			results <- CheckS3Bucket(f.client, n)
		}(name)
	}
	var out []S3Result
	for range bucketNames {
		out = append(out, <-results)
	}
	close(results)
	return out
}