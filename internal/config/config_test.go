package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// reset restaura o singleton entre testes e roda Init de novo ao sair.
func reset(t *testing.T) {
	t.Helper()
	cfg = nil
	viper.Reset()
	t.Cleanup(func() {
		cfg = nil
		viper.Reset()
	})
}

// @spec:config — env GOFENCE_TLS_SKIP_VERIFY=true é respeitada
func TestTLSSkipVerifyFromEnv(t *testing.T) {
	reset(t)
	t.Setenv("GOFENCE_TLS_SKIP_VERIFY", "true")
	Init()
	if !Get().TLSSkipVerify {
		t.Errorf("expected TLSSkipVerify=true from GOFENCE_TLS_SKIP_VERIFY=true")
	}
}

// @spec:config — default seguro: verificação de certificado ativa
func TestTLSSkipVerifyDefaultIsFalse(t *testing.T) {
	reset(t)
	os.Unsetenv("GOFENCE_TLS_SKIP_VERIFY")
	Init()
	if Get().TLSSkipVerify {
		t.Errorf("expected TLSSkipVerify=false by default (secure default), got true")
	}
}

// @spec:config — config.yaml sobrescreve o default
func TestConfigFileOverridesDefault(t *testing.T) {
	reset(t)
	dir := t.TempDir()
	yaml := "concurrency: 42\nrate_profile: sneaky\ntls_skip_verify: true\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(dir)
	for key, env := range envBindings {
		_ = viper.BindEnv(key, env)
	}
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}
	if viper.GetInt("concurrency") != 42 {
		t.Errorf("expected concurrency=42 from yaml, got %d", viper.GetInt("concurrency"))
	}
	if viper.GetString("rate_profile") != "sneaky" {
		t.Errorf("expected rate_profile=sneaky from yaml, got %q", viper.GetString("rate_profile"))
	}
	if !viper.GetBool("tls_skip_verify") {
		t.Errorf("expected tls_skip_verify=true from yaml")
	}
}

// @spec:config — env sobrescreve config.yaml
func TestEnvOverridesConfigFile(t *testing.T) {
	reset(t)
	dir := t.TempDir()
	yaml := "concurrency: 42\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("GOFENCE_CONCURRENCY", "7")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(dir)
	for key, env := range envBindings {
		_ = viper.BindEnv(key, env)
	}
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}
	Init()
	if Get().Concurrency != 7 {
		t.Errorf("expected env (7) to override yaml (42), got %d", Get().Concurrency)
	}
}
