package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/pkg/httpclient"
)

type OSINTResult struct {
	Provider string                 `json:"provider"`
	Data     map[string]interface{} `json:"data"`
}

type OSINTClient struct {
	client *httpclient.Client
	cfg    *config.Config
}

func NewOSINTClient(c *httpclient.Client, cfg *config.Config) *OSINTClient {
	return &OSINTClient{client: c, cfg: cfg}
}

func (o *OSINTClient) Query(target, provider string) ([]OSINTResult, error) {
	switch provider {
	case "shodan":
		return o.queryShodan(target)
	case "censys":
		return o.queryCensys(target)
	case "securitytrails":
		return o.querySecurityTrails(target)
	case "crtsh":
		return o.queryCRTSh(target)
	case "hackertarget":
		return o.queryHackerTarget(target)
	case "whois":
		return o.queryWhois(target)
	case "all":
		var all []OSINTResult
		// Keyless providers first so OSINT works with no API keys configured.
		for _, p := range []string{"crtsh", "hackertarget", "whois", "shodan", "censys", "securitytrails"} {
			res, err := o.queryByProvider(p, target)
			if err != nil {
				continue
			}
			all = append(all, res...)
		}
		return all, nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

func (o *OSINTClient) queryByProvider(p, target string) ([]OSINTResult, error) {
	switch p {
	case "shodan":
		return o.queryShodan(target)
	case "censys":
		return o.queryCensys(target)
	case "securitytrails":
		return o.querySecurityTrails(target)
	case "crtsh":
		return o.queryCRTSh(target)
	case "hackertarget":
		return o.queryHackerTarget(target)
	case "whois":
		return o.queryWhois(target)
	}
	return nil, nil
}

func (o *OSINTClient) queryCRTSh(target string) ([]OSINTResult, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", target)
	body, err := o.doRequest(url, "")
	if err != nil {
		return nil, err
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return []OSINTResult{{Provider: "crtsh", Data: map[string]interface{}{"certificates": data}}}, nil
}

func (o *OSINTClient) queryHackerTarget(target string) ([]OSINTResult, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", target)
	body, err := o.doRequest(url, "")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var hosts []string
	for _, l := range lines {
		if l != "" {
			hosts = append(hosts, l)
		}
	}
	return []OSINTResult{{Provider: "hackertarget", Data: map[string]interface{}{"hosts": hosts}}}, nil
}

func (o *OSINTClient) queryWhois(target string) ([]OSINTResult, error) {
	raw, err := whoisQuery(target)
	if err != nil {
		return nil, err
	}
	return []OSINTResult{{Provider: "whois", Data: map[string]interface{}{"raw": raw}}}, nil
}

var whoisServerRe = regexp.MustCompile(`(?i)whois:\s*(\S+)`)

func whoisQuery(query string) (string, error) {
	first, err := rawWhois("whois.iana.org:43", query)
	if err != nil {
		return "", err
	}
	if m := whoisServerRe.FindStringSubmatch(first); len(m) > 1 {
		if second, err := rawWhois(m[1]+":43", query); err == nil {
			return second, nil
		}
	}
	return first, nil
}

func rawWhois(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	buf, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (o *OSINTClient) doRequest(url, apiKey string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("X-Api-Key", apiKey)
		}
		resp, err := o.client.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = fmt.Errorf("rate limited (429)")
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, fmt.Errorf("request failed after retries: %v", lastErr)
}

func (o *OSINTClient) queryShodan(target string) ([]OSINTResult, error) {
	if o.cfg.ShodanKey == "" {
		return nil, fmt.Errorf("shodan API key not configured")
	}
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", target, o.cfg.ShodanKey)
	body, err := o.doRequest(url, o.cfg.ShodanKey)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return []OSINTResult{{Provider: "shodan", Data: data}}, nil
}

func (o *OSINTClient) queryCensys(target string) ([]OSINTResult, error) {
	if o.cfg.CensysID == "" || o.cfg.CensysSecret == "" {
		return nil, fmt.Errorf("censys credentials not configured")
	}
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", target)
	body, err := o.doRequest(url, o.cfg.CensysSecret)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return []OSINTResult{{Provider: "censys", Data: data}}, nil
}

func (o *OSINTClient) querySecurityTrails(target string) ([]OSINTResult, error) {
	if o.cfg.SecurityTrailsKey == "" {
		return nil, fmt.Errorf("securitytrails key not configured")
	}
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s", target)
	body, err := o.doRequest(url, o.cfg.SecurityTrailsKey)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return []OSINTResult{{Provider: "securitytrails", Data: data}}, nil
}

func (o *OSINTClient) FormatOutput(results []OSINTResult) string {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("=== %s ===\n", r.Provider))
		b, _ := json.MarshalIndent(r.Data, "", "  ")
		sb.Write(b)
		sb.WriteString("\n")
	}
	return sb.String()
}
