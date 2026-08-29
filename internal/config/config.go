package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	ShodanKey       string `mapstructure:"shodan_key"`
	CensysID        string `mapstructure:"censys_id"`
	CensysSecret    string `mapstructure:"censys_secret"`
	SecurityTrailsKey string `mapstructure:"securitytrails_key"`
	RateProfile     string `mapstructure:"rate_profile"`
	Concurrency     int    `mapstructure:"concurrency"`
	DBPath          string `mapstructure:"db_path"`
	NoTUI           bool   `mapstructure:"no_tui"`
	JSONOutput      bool   `mapstructure:"json_output"`
	WordlistPath    string `mapstructure:"wordlist_path"`
	ProxyURL        string `mapstructure:"proxy_url"`
	TLSSkipVerify   bool   `mapstructure:"tls_skip_verify"`
}

var cfg *Config

func Init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	home, _ := os.UserHomeDir()
	viper.AddConfigPath(filepath.Join(home, ".gofence"))
	viper.AddConfigPath(".")

	viper.SetEnvPrefix("GOFENCE")
	viper.AutomaticEnv()

	viper.SetDefault("rate_profile", "normal")
	viper.SetDefault("concurrency", 100)
	viper.SetDefault("db_path", "gofence.db")
	viper.SetDefault("tls_skip_verify", true)

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
