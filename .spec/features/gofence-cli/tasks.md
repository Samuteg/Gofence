# Tasks: gofence-cli

> feature: gofence-cli

## T-001 — Projeto Go, módulos e dependências [concluida]

- Refs: US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009, US-010, US-011, US-012, US-013, US-014, US-015
- Arquivos: go.mod, go.sum, main.go
- Notas: `go mod init github.com/nixteg/gofence`, adicionar todas as dependências (cobra, viper, modernc.org/sqlite, miekg/dns, bubbletea, golang.org/x/time/rate, x/net/html, golang.org/x/crypto/ssh, yaml.v3)

## T-002 — Configuração (Viper) [concluida]

- Refs: US-002, US-015
- Arquivos: internal/config/config.go
- Notas: Layering flags > env GOFENCE_* > YAML > defaults. Chaves: shodan_key, censys_id, censys_secret, securitytrails_key, rate_profile, concurrency

## T-003 — HTTP client customizado [concluida]

- Refs: US-004, US-006, US-007, US-010
- Arquivos: pkg/httpclient/client.go
- Notas: HTTP/2, TLS skip verify, proxy rotativo via env HTTP_PROXY, timeout configurável

## T-004 — ScopeGuard [concluida]

- Refs: US-012, AC-026, AC-027
- Arquivos: internal/data/scope.go, internal/data/db.go
- Notas: Interface ScopeGuard com IsAllowed(ip net.IP) bool. Implementação padrão consulta SQLite. Middleware bloqueia operações fora do escopo com log STDERR

## T-005 — SQLite schema e models [concluida]

- Refs: US-011, AC-023, AC-024, AC-025
- Arquivos: internal/data/db.go, internal/data/models.go, cmd/workspace.go, cmd/helpers.go
- Notas: Tabelas: workspaces, scope, hosts, ports, findings, kv. Auto-migrate no init. Workspace CRUD (new, list, set-active, scope). helpers.go: openWorkspace, hostOf, writeTempWordlist

## T-006 — Root command e detecção TUI/headless [concluida]

- Refs: US-013, US-014, AC-028, AC-030
- Arquivos: cmd/root.go, main.go
- Notas: Se stdout é TTY e sem --no-tui, lança TUI. Caso contrário, headless. Flag --json força JSON no stdout

## T-007 — Rate limiter [concluida]

- Refs: US-015, AC-032, AC-033, AC-034
- Arquivos: internal/ux/ratelimit.go
- Notas: Perfis: sneaky (1/s), normal (50/s), aggressive (ilimitado). Implementação com golang.org/x/time/rate. Injetado no httpclient e no portscanner

## T-008 — DNS brute-force e AXFR [concluida]

- Refs: US-001, AC-001, AC-002, AC-003
- Arquivos: internal/recon/dns.go, internal/recon/dns_nameserver_test.go, cmd/dns.go, internal/assets/assets.go
- Notas: Goroutines com semáforo (concurrency flag). AXFR via miekg/dns. STDOUT: subdomínio + IP. Wordlist embutida (subdomains.txt via go:embed) ou via flag -w. Nameserver configurável via flag --nameserver (host:porta) para o brute-force — testado com DNS fake em memória

## T-009 — OSINT clients [concluida]

- Refs: US-002, AC-004, AC-005
- Arquivos: internal/recon/osint.go, cmd/osint.go
- Notas: Shodan (api.shodan.io), Censys (search.censys.io), SecurityTrails. Retry com backoff em 429. Output JSON consolidado

## T-010 — Port scanner TCP/UDP [concluida]

- Refs: US-003, AC-006, AC-007
- Arquivos: internal/recon/portscan.go, cmd/port.go
- Notas: net.DialTimeout com goroutines. Top 1000 TCP / top 100 UDP. ScopeGuard antes de cada dial. Output: porta, serviço, estado

## T-011 — Fuzzer web [concluida]

- Refs: US-004, AC-008, AC-009, AC-010
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go, internal/assets/assets.go, internal/ux/waf.go
- Notas: Stream de wordlist (bufio.Scanner), substituição /FUZZ, header FUZZ, POST FUZZ. Wordlist embutida (paths.txt). WAF detector com backoff. Output: URL, status code, tamanho

## T-012 — Analisador TLS [concluida]

- Refs: US-005, AC-011, AC-012
- Arquivos: internal/surface/tls.go, cmd/tls.go
- Notas: crypto/tls Dial. Extrai subject, issuer, validade, SHA-256, cipher suites. Flag --strict: alert para < TLS 1.2

## T-013 — Crawler AST [concluida]

- Refs: US-006, AC-013, AC-014
- Arquivos: internal/surface/crawler.go, cmd/crawl.go, internal/ux/waf.go
- Notas: x/net/html parser. BFS com profundidade max. Regex para JWT, AWS keys, secrets. WAF detector integrado. Output: URLs + alertas STDERR

## T-014 — Templates de vulnerabilidade [concluida]

- Refs: US-007, AC-015, AC-016
- Arquivos: internal/surface/vulns.go, cmd/vulns.go, internal/assets/assets.go
- Notas: YAML parser. Template com requests[].method/path/body e matchers[].type (regex/status/word). Templates embutidos (exposed-aws.yaml, exposed-git.yaml). Execução em lote por diretório

## T-015 — Gerador de payloads [concluida]

- Refs: US-008, AC-017, AC-018
- Arquivos: internal/exploit/payload.go, cmd/payload.go
- Notas: Templates de one-liners: nc (bash), python, perl, powershell. Bind e reverse shell. Input: --type, --ip, --port

## T-016 — Multi-handler [concluida]

- Refs: US-009, AC-019, AC-020
- Arquivos: internal/exploit/handler.go, cmd/listen.go
- Notas: net.Listen TCP/UDP. sync.Map para sessões. Goroutine por conexão. Output: sessões ativas

## T-017 — Engine de brute force [concluida]

- Refs: US-010, AC-021, AC-022
- Arquivos: internal/exploit/brute.go, cmd/brute.go
- Notas: SSH (x/crypto/ssh), FTP (net), HTTP Basic. Backoff exponencial após 5 falhas. Flag --no-backoff. Output: credencial encontrada

## T-018 — TUI Bubbletea [concluida]

- Refs: US-013, AC-028, AC-029
- Arquivos: internal/ux/tui.go
- Notas: Model com 4 painéis: hosts, ports, sessions, log. Atualização via channels. Lipgloss para estilo

## T-019 — Modo headless/pipeline [concluida]

- Refs: US-014, AC-030, AC-031
- Arquivos: internal/ux/headless.go
- Notas: Detecção isatty. JSON puro no STDOUT. Pipes: stdin de um comando = stdout do anterior. Flag --json

## T-020 — Integração final e testes [concluida]

- Refs: US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009, US-010, US-011, US-012, US-013, US-014, US-015
- Arquivos: main.go, cmd/root.go, cmd/dns.go, cmd/osint.go, cmd/port.go, cmd/fuzz.go, cmd/tls.go, cmd/crawl.go, cmd/vulns.go, cmd/payload.go, cmd/listen.go, cmd/brute.go, cmd/workspace.go, cmd/report.go
- Notas: Verificar que todos os comandos estão registrados no root. Testes de integração básicos. Build estático: `go build -ldflags '-s -w'`
