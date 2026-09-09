// Package httpclient centraliza a configuração do cliente HTTP (timeouts,
// proxy e verificação de TLS) usada por todos os módulos de rede.
package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/nixteg/gofence/internal/config"
)

type Client struct {
	HTTP *http.Client
}

// New constrói o client. skipVerify desativa a verificação de certificado —
// o default do projeto é false (seguro); só passe true sob demanda.
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

// NewFromEnv resolve proxy e TLS skip na ordem: env GOFENCE_TLS_SKIP_VERIFY /
// GOFENCE_PROXY_URL > config.yaml > default seguro. Mantém fallback para
// HTTP_PROXY/http_proxy (padrão de ecossistema Go).
func NewFromEnv() *Client {
	skipVerify := resolveTLSSkipVerify()
	return New(skipVerify, resolveProxy(), 30*time.Second)
}

func resolveTLSSkipVerify() bool {
	if v := os.Getenv("GOFENCE_TLS_SKIP_VERIFY"); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return config.Get().TLSSkipVerify
}

func resolveProxy() string {
	if v := os.Getenv("GOFENCE_PROXY_URL"); v != "" {
		return v
	}
	if v := config.Get().ProxyURL; v != "" {
		return v
	}
	if v := os.Getenv("HTTP_PROXY"); v != "" {
		return v
	}
	return os.Getenv("http_proxy")
}
