# Design: gofence-cli

> feature: gofence-cli

## Arquitetura Geral

```
gofence
├── cmd/                  # Cobra commands (entry points)
│   ├── root.go           # Root command, TUI vs headless detection
│   ├── dns.go            # US-001: DNS brute-force + AXFR
│   ├── osint.go          # US-002: Shodan/Censys/SecurityTrails
│   ├── port.go           # US-003: TCP/UDP port scan
│   ├── fuzz.go           # US-004: HTTP fuzzer
│   ├── tls.go            # US-005: TLS inspection
│   ├── crawl.go          # US-006: AST-based crawler
│   ├── vulns.go          # US-007: Vulnerability templates
│   ├── payload.go        # US-008: Payload generator
│   ├── listen.go         # US-009: Multi-handler
│   ├── brute.go          # US-010: Brute force engine
│   ├── workspace.go      # US-011: Workspace management
│   └── ui.go             # US-013: TUI launcher
├── internal/
│   ├── recon/            # Pilar 1
│   │   ├── dns.go        # Concurrent DNS resolver (miekg/dns)
│   │   ├── osint.go      # API clients (Shodan, Censys, SecurityTrails)
│   │   └── portscan.go   # Async TCP/UDP scanner
│   ├── surface/          # Pilar 2
│   │   ├── fuzzer.go     # Stream-based HTTP fuzzer
│   │   ├── tls.go        # TLS analyzer (crypto/tls)
│   │   ├── crawler.go    # HTML AST parser + regex secret detection
│   │   └── vulns.go      # YAML template engine
│   ├── exploit/          # Pilar 3
│   │   ├── payload.go    # Payload crafter (reverse/bind shells)
│   │   ├── handler.go    # TCP/UDP multi-session listener
│   │   └── brute.go      # Modular brute force (SSH, FTP, HTTP)
│   ├── data/             # Pilar 4
│   │   ├── db.go         # SQLite setup + migrations
│   │   ├── models.go     # ORM-like structs (Workspace, Host, Port, Finding)
│   │   ├── scope.go      # ScopeGuard middleware
│   │   └── workspace.go  # Workspace CRUD
│   ├── ux/               # Pilar 5
│   │   ├── tui.go        # Bubbletea dashboard
│   │   ├── headless.go   # Pipeline mode + JSON output
│   │   └── ratelimit.go  # Rate limiter profiles (golang.org/x/time/rate)
│   └── config/           # Configuration
│       └── config.go     # Viper-based config (env, YAML, flags)
├── pkg/
│   └── httpclient/       # Custom HTTP client
│       └── client.go     # HTTP/2, TLS skip, proxy support
├── go.mod
├── go.sum
└── main.go
```

## Decisões de Arquitetura

### D-001: modernc.org/sqlite (pure Go) — ASM-001

Escolha: `modernc.org/sqlite` em vez de `mattn/go-sqlite3` (CGO).

Razão: binário estático sem dependência de CGO. Trade-off: performance ~20% menor, aceitável para uso local.

### D-002: Config layering (Viper) — ASM-005

Ordem de prioridade: flags CLI > env vars (`GOFENCE_*`) > arquivo YAML (`~/.gofence/config.yaml`) > defaults.

### D-003: ScopeGuard como middleware — ASM-008

Interface `ScopeGuard` é injetada em toda função de rede. Implementação padrão consulta SQLite do workspace ativo. Funções de rede NÃO podem existir sem passar pelo guard.

### D-004: TUI condicional — ASM-006

Se stdout é terminal (detecção via `os.Stdout.Stat()`), entra TUI. Caso contrário, modo headless. Flag `--no-tui` força headless.

### D-005: Crawler não respeita robots.txt — Q-003

Para pentest, robots.txt é ignorado. Essa é uma escolha deliberada de segurança ofensiva.

### D-006: Templates no formato Nuclei-like — Q-004

YAML com `requests[].method`, `requests[].path`, `matchers[].type: regex|status|word`. Formato compatível com Nuclei para facilitar adoção.

### D-007: Brute force com proteção — Q-002

Implementar backoff exponencial após 5 tentativas falhas. Flag `--no-backoff` desativa (para testes contra alvos sem proteção).

### D-008: Rate limit com retry em OSINT — Q-006

Retry com exponential backoff (3 tentativas) em erro 429. Se 429 persistir, falha imediata com mensagem clara.

### D-009: Workspace soft delete — Q-007

Soft delete (coluna `deleted_at`). Mantém dados históricos para auditoria.

### D-010: Auto-detect JSON mode — Q-008

Flag `--json` explícito E detecção automática (`!isatty(stdout)`). Prioridade: flag > auto-detect.

### D-011: HTTP client customizado

Reutilizável em todos os módulos HTTP (fuzzer, crawler, OSINT, brute). Suporta: HTTP/2, TLS skip verify, proxy rotativo, rate limiting embutido.

### D-012: Handler multi-session

Cada conexão recebida vira uma goroutine. Sessões armazenadas em `sync.Map`. Upgrade de TTY via script Python embarcado (pty spawn).

## Fluxo de Dados

```
User → Cobra Command → ScopeGuard Check → Module Logic → SQLite Persist → STDOUT/STDERR
                         ↓ (rejeita)
                    Log "Out-of-Scope Blocked"
```

Toda operação de rede passa por ScopeGuard ANTES de qualquer I/O de rede.
