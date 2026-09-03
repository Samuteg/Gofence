# Tasks: Scope enforcement

> feature: scope-enforcement

## T-021 — Guarda a partir do workspace + checagem de host [concluida]
- Refs: US-016, AC-035, AC-036, AC-038, AC-039
- Arquivos: internal/data/scope.go
- Notas: GuardForWorkspace(db, wsID) carrega CIDRs via ScopeGetCIDRs. CheckHost(g, host, action) aceita IP, ip:porta, URL ou hostname (resolve via ResolveIP; irreconhecível = bloqueado). FilterAllowed(g, ips) filtra listas (DNS). Testes herméticos em scope_test.go (IP literal, ip:porta, .invalid sem rede)

## T-022 — Ligar a guarda nos comandos de rede [concluida]
- Refs: US-016, AC-035, AC-036, AC-037, AC-038, AC-039
- Arquivos: cmd/helpers.go, cmd/dns.go, cmd/osint.go, cmd/port.go, cmd/fuzz.go, cmd/tls.go, cmd/crawl.go, cmd/vulns.go, cmd/brute.go
- Notas: requireScope(db, wsID, host, action) em helpers.go retorna erro sem workspace (AC-037), com escopo vazio (AC-038) ou alvo fora (AC-035, já logado). dns filtra resultado a resultado (AC-039). listen/payload/report/workspace ficam de fora (sem alvo)

## T-023 — Teste de CLI da guarda com banco temporário [concluida]
- Refs: US-016, AC-037, AC-038
- Arquivos: cmd/helpers_test.go
- Notas: package cmd com t.TempDir(). Cobre requireScope sem workspace, com escopo vazio e alvo dentro do escopo
