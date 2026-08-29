package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	client  *httpclient.Client
	cfg     *config.Config
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
	case "all":
		var all []OSINTResult
		for _, p := range []string{"shodan", "censys", "securitytrails"} {
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
	}
	return nil, nil
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
