package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// cfg guarda a configuração resolvida após Init.
var cfg *Config

type Config struct {
	ShodanKey         string `mapstructure:"shodan_key"`
	CensysID          string `mapstructure:"censys_id"`
	CensysSecret      string `mapstructure:"censys_secret"`
	SecurityTrailsKey string `mapstructure:"securitytrails_key"`
	RateProfile       string `mapstructure:"rate_profile"`
	Concurrency       int    `mapstructure:"concurrency"`
	DBPath            string `mapstructure:"db_path"`
	NoTUI             bool   `mapstructure:"no_tui"`
	JSONOutput        bool   `mapstructure:"json_output"`
	WordlistPath      string `mapstructure:"wordlist_path"`
	ProxyURL          string `mapstructure:"proxy_url"`
	TLSSkipVerify     bool   `mapstructure:"tls_skip_verify"`
}

// envBindings mapeia cada chave à sua env var GOFENCE_*. O BindEnv explícito é
// necessário: o viper só consulta env para chaves que ele conhece — sem isso,
// chaves sem default (ex.: shodan_key) nunca seriam lidas do ambiente.
// Precedência final: flag CLI > env GOFENCE_* > config.yaml > default
// (as flags são resolvidas no cmd via Flags().Changed).
var envBindings = map[string]string{
	"shodan_key":         "GOFENCE_SHODAN_KEY",
	"censys_id":          "GOFENCE_CENSYS_ID",
	"censys_secret":      "GOFENCE_CENSYS_SECRET",
	"securitytrails_key": "GOFENCE_SECURITYTRAILS_KEY",
	"rate_profile":       "GOFENCE_RATE_PROFILE",
	"concurrency":        "GOFENCE_CONCURRENCY",
	"db_path":            "GOFENCE_DB_PATH",
	"no_tui":             "GOFENCE_NO_TUI",
	"json_output":        "GOFENCE_JSON_OUTPUT",
	"wordlist_path":      "GOFENCE_WORDLIST_PATH",
	"proxy_url":          "GOFENCE_PROXY_URL",
	"tls_skip_verify":    "GOFENCE_TLS_SKIP_VERIFY",
}

func Init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	home, _ := os.UserHomeDir()
	viper.AddConfigPath(filepath.Join(home, ".gofence"))
	viper.AddConfigPath(".")

	for key, env := range envBindings {
		_ = viper.BindEnv(key, env)
	}

	viper.SetDefault("rate_profile", "normal")
	viper.SetDefault("concurrency", 100)
	viper.SetDefault("db_path", "gofence.db")
	// Seguro por padrão: verificação de certificado ativa. Desative
	// explicitamente (GOFENCE_TLS_SKIP_VERIFY=true ou tls_skip_verify: true)
	// ao varrer alvos com TLS quebrado/self-signed.
	viper.SetDefault("tls_skip_verify", false)

	_ = viper.ReadInConfig()

	cfg = &Config{}
	_ = viper.Unmarshal(cfg)
}

func Get() *Config {
	if cfg == nil {
		Init()
	}
	return cfg
}
