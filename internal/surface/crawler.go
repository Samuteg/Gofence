package surface

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"golang.org/x/net/html"
	"golang.org/x/time/rate"
)

type CrawlResult struct {
	URLs    []string
	Secrets []Secret
}

type Secret struct {
	Type    string `json:"type"`
	Source  string `json:"source"`
	Snippet string `json:"snippet"`
}

var (
	jwtRegex       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	awsKeyRegex    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretRegex = regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+=]{40}`)
	apiKeyRegex    = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}`)
)

type Crawler struct {
	client      *httpclient.Client
	MaxDepth    int
	Concurrency int
	WAF         *ux.WAFDetector
	Limiter     *rate.Limiter
	visited     sync.Map
	ctx         context.Context
	urls        []string
	secrets     []Secret
	mu          sync.Mutex
}

func NewCrawler(client *httpclient.Client, maxDepth, concurrency int) *Crawler {
	if maxDepth <= 0 {
		maxDepth = 3
	}
	if concurrency <= 0 {
		concurrency = 20
	}
	return &Crawler{client: client, MaxDepth: maxDepth, Concurrency: concurrency}
}

func (c *Crawler) Crawl(startURL string) *CrawlResult {
	return c.CrawlContext(context.Background(), startURL)
}

// CrawlContext executa o crawl respeitando ctx (cancelamento via Ctrl+C):
// nenhuma nova requisição é feita após o cancelamento.
func (c *Crawler) CrawlContext(ctx context.Context, startURL string) *CrawlResult {
	baseURL, _ := url.Parse(startURL)
	c.ctx = ctx
	c.crawlLevel(startURL, 0, baseURL)

	return &CrawlResult{
		URLs:    c.urls,
		Secrets: c.secrets,
	}
}

func (c *Crawler) crawlLevel(targetURL string, depth int, base *url.URL) {
	if depth > c.MaxDepth {
		return
	}
	if c.ctx != nil && c.ctx.Err() != nil {
		return
	}
	if _, loaded := c.visited.LoadOrStore(targetURL, true); loaded {
		return
	}
	if c.WAF != nil && c.WAF.Triggered() {
		return
	}
	if c.Limiter != nil {
		if err := c.Limiter.Wait(c.ctx); err != nil {
			return
		}
	}

	resp, err := c.client.HTTP.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if c.WAF != nil {
		if detected, _ := c.WAF.Hit(resp.StatusCode, body); detected {
			fmt.Fprintf(os.Stderr, "WAF detected (%s) on %s: skipping\n", c.WAF.Signature(), targetURL)
			return
		}
	}

	c.extractSecrets(targetURL, string(body))

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "href" || attr.Key == "src" || attr.Key == "action" {
					link := c.resolveURL(attr.Val, base)
					if link != "" && strings.HasPrefix(link, base.Scheme+"://"+base.Host) {
						c.mu.Lock()
						c.urls = append(c.urls, link)
						c.mu.Unlock()
						if depth+1 <= c.MaxDepth {
							c.crawlLevel(link, depth+1, base)
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
}

func (c *Crawler) resolveURL(raw string, base *url.URL) string {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") {
		return ""
	}
	rel, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(rel)
	return abs.String()
}

func (c *Crawler) extractSecrets(source, body string) {
	checks := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"JWT", jwtRegex},
		{"AWS_KEY", awsKeyRegex},
		{"AWS_SECRET", awsSecretRegex},
		{"GENERIC_KEY", apiKeyRegex},
	}

	for _, check := range checks {
		matches := check.re.FindAllString(body, -1)
		for _, m := range matches {
			snippet := m
			if len(snippet) > 40 {
				snippet = snippet[:40] + "..."
			}
			c.mu.Lock()
			c.secrets = append(c.secrets, Secret{
				Type:    check.name,
				Source:  source,
				Snippet: snippet,
			})
			c.mu.Unlock()
			fmt.Fprintf(os.Stderr, "[SECRET] type=%s source=%s snippet=%s\n", check.name, source, snippet)
		}
	}
}
