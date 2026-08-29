package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Client struct {
	HTTP *http.Client
}

func New(skipVerify bool, proxyURL string, timeout time.Duration) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	}

	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	return &Client{
		HTTP: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

func NewFromEnv() *Client {
	skipVerify := os.Getenv("GOFENCE_TLS_SKIP_VERIFY") != "false"
	proxy := os.Getenv("HTTP_PROXY")
	if proxy == "" {
		proxy = os.Getenv("http_proxy")
	}
	return New(skipVerify, proxy, 30*time.Second)
}
