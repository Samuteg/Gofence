package recon

import (
	"time"
)

func init() {
	RegisterScript("ssh", "banner", func(host string, port int) ScriptResult {
		banner := bannerProbe(host, port, 2*time.Second)
		if banner == "" {
			return ScriptResult{Service: "ssh", Name: "banner", OK: false, Detail: "no banner"}
		}
		return ScriptResult{Service: "ssh", Name: "banner", OK: true, Detail: truncate(banner)}
	})

	RegisterScript("ssh", "auth-methods", func(host string, port int) ScriptResult {
		// Checagem não-destrutiva: abre a conexão e verifica se o serviço
		// responde à identificação SSH (versão). Não tenta autenticar.
		banner := bannerProbe(host, port, 2*time.Second)
		if banner == "" {
			return ScriptResult{Service: "ssh", Name: "auth-methods", OK: false, Detail: "no banner"}
		}
		return ScriptResult{Service: "ssh", Name: "auth-methods", OK: true, Detail: "service responds to identification"}
	})
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}