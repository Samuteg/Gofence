# gofence

Ferramenta CLI de segurança ofensiva (pentest) escrita em Go — binário único,
statically linked, focada em reconhecimento, mapeamento de superfície e
exploração. Arquitetura modular em 5 pilares, com armazenamento local em
SQLite e modos interativo (TUI) e headless (pipeline UNIX).

> ⚠️ **Uso autorizado apenas.** Esta ferramenta destina-se a testes de intrusão
> com autorização explícita (escopo contratado). O módulo de ScopeGuard bloqueia
> qualquer operação de rede fora do CIDR declarado no workspace.

---

## Índice

- [Instalação](#instalação)
- [Visão geral dos comandos](#visão-geral-dos-comandos)
- [Flags globais](#flags-globais)
- [Configuração](#configuração)
- [Pilar 1 — Coleta e Recon](#pilar-1--coleta-e-recon)
- [Pilar 2 — Superfície e Vulnerabilidades](#pilar-2--superfície-e-vulnerabilidades)
- [Pilar 3 — Exploração e Helpers](#pilar-3--exploração-e-helpers)
- [Pilar 4 — Escopo e Gestão de Dados](#pilar-4--escopo-e-gestão-de-dados)
- [Pilar 5 — UX e Arquitetura](#pilar-5--ux-e-arquitetura)
- [Exemplos de fluxo (pipeline)](#exemplos-de-fluxo-pipeline)
- [Banco de dados (SQLite)](#banco-de-dados-sqlite)
- [Desenvolvimento e testes](#desenvolvimento-e-testes)

---

## Instalação

### Pré-requisitos

- Go 1.22+ (testado em 1.26.5)
- Acesso de rede conforme o alvo autorizado

### Build a partir do código-fonte

```bash
git clone <repo> gofence
cd gofence
go build -o gofence .
```

### Build estático (sem CGO, binário portátil)

```bash
CGO_ENABLED=0 go build -ldflags '-s -w' -o gofence .
```

> O projeto usa `modernc.org/sqlite` (pure Go) — **nenhuma dependência de CGO**,
> então o binário estático funciona em qualquer Linux amd64/arm64.

### Verificar instalação

```bash
./gofence --help
```

---

## Visão geral dos comandos

| Comando | Descrição |
|---------|-----------|
| `gofence` (sem args) | Abre a TUI (se stdout for um terminal) |
| `gofence dns <alvo>` | Brute-force de subdomínios e transferência de zona (AXFR) |
| `gofence osint <alvo>` | Consulta APIs Shodan, Censys e SecurityTrails |
| `gofence port <ip/cidr>` | Varredura TCP/UDP de portas |
| `gofence fuzz <url>` | Fuzzer web de caminhos, cabeçalhos e POST |
| `gofence tls <host:porta>` | Análise de certificado TLS e cifras |
| `gofence crawl <url>` | Crawler AST com detecção de segredos |
| `gofence vulns <alvo>` | Executa templates de vulnerabilidade (formato Nuclei) |
| `gofence payload` | Gera payloads de reverse/bind shell |
| `gofence listen` | Multi-handler para conexões reversas |
| `gofence brute <serviço>` | Brute force de dicionário (ssh/http/ftp) |
| `gofence workspace` | Gerencia workspaces e escopo |

---

## Flags globais

Aplicam-se a todos os comandos (definidas no root):

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--config <arquivo>` | `~/.gofence/config.yaml` | Arquivo de configuração YAML |
| `--no-tui` | `false` | Força modo headless (desativa TUI) |
| `--json` | `false` | Força saída JSON no STDOUT |
| `--rate <perfil>` | `normal` | Perfil de rate limit: `sneaky`\|`normal`\|`aggressive` |
| `--concurrency <n>` | `100` | Máximo de goroutines simultâneas |
| `--db <caminho>` | `~/.gofence/gofence.db` | Caminho do banco SQLite |

**Ordem de precedência da configuração:**
`flags CLI` > `env GOFENCE_*` > `~/.gofence/config.yaml` > padrões.

---

## Configuração

Crie `~/.gofence/config.yaml` (ou use variáveis de ambiente `GOFENCE_*`):

```yaml
shodan_key: "SUA_CHAVE_SHODAN"
censys_id: "SEU_CENSYS_ID"
censys_secret: "SEU_CENSYS_SECRET"
securitytrails_key: "SUA_CHAVE_SECURITYTRAILS"
rate_profile: "normal"      # sneaky | normal | aggressive
concurrency: 100
db_path: "~/.gofence/gofence.db"
tls_skip_verify: true       # ignora certificados TLS inválidos
```

Ou via ambiente:

```bash
export GOFENCE_SHODAN_KEY="SUA_CHAVE_SHODAN"
export GOFENCE_CENSYS_ID="..."
export GOFENCE_CENSYS_SECRET="..."
export GOFENCE_SECURITYTRAILS_KEY="..."
```

> **Segurança:** chaves nunca devem ser hard-coded (princípio P-002 da
> constituição). Use sempre env vars ou arquivo de configuração fora do repo.

---

## Pilar 1 — Coleta e Recon

### `dns` — Descoberta de subdomínios

```bash
# Brute-force de subdomínios com wordlist
gofence dns alvo.com -w /caminho/wordlist.txt

# Limitar concorrência
gofence dns alvo.com -w wordlist.txt --concurrency 500

# Transferência de zona (AXFR)
gofence dns alvo.com --axfr --nameserver ns1.alvo.com
```

Saída (STDOUT, uma por linha): `subdominio IP`

### `osint` — Inteligência de fontes externas

```bash
# Consultar todos os providers configurados
gofence osint 1.2.3.4 --provider all

# Apenas Shodan
gofence osint alvo.com --provider shodan
```

Providers: `shodan` | `censys` | `securitytrails` | `all`.
Em erro HTTP 429, o cliente faz retry com backoff exponencial (3 tentativas).

### `port` — Varredura de portas

```bash
# Top 1000 portas TCP em um IP
gofence port 10.0.0.5 --top 1000

# Portas específicas
gofence port 10.0.0.5 --ports 22,80,443,8080

# Varredura UDP (top 100)
gofence port 10.0.0.5 --udp --top 100

# CIDR inteiro
gofence port 10.0.0.0/24 --top 100
```

> Toda operação passa pelo **ScopeGuard** — IPs fora do escopo do workspace
> são descartados com log `Out-of-Scope Blocked` no STDERR.

---

## Pilar 2 — Superfície e Vulnerabilidades

### `fuzz` — Fuzzer web de alta performance

Lê a wordlist como **stream** (não carrega tudo na RAM — suporta wordlists
gigantes).

```bash
# Fuzzing de caminhos
gofence fuzz web https://alvo.com/FUZZ -w wordlist.txt

# Fuzzing de cabeçalho
gofence fuzz web https://alvo.com/ -w hosts.txt --header "Host: FUZZ"

# Fuzzing de dados POST
gofence fuzz web https://alvo.com/login -w passwords.txt --data "user=admin&pass=FUZZ"
```

Imprime no STDOUT apenas respostas com status ≠ 404: `[status] url (size: N)`.

### `tls` — Análise de certificado

```bash
gofence tls alvo.com:443
gofence tls 10.0.0.5:8443 --strict   # alerta se TLS < 1.2
```

Saída JSON: subject, issuer, validade, fingerprint SHA-256, cifras, protocolos.

### `crawl` — Crawler baseado em AST

```bash
gofence crawl https://alvo.com/ --depth 3
```

- Extrai links (BFS até a profundidade configurada)
- Detecta segredos (JWT, AWS keys, API keys) — alertas no **STDERR**
- Ignora `robots.txt` (decisão deliberada para pentest)

### `vulns` — Templates de vulnerabilidade

Formato compatível com **Nuclei** (YAML com `requests[]` e `matchers[]`):

```bash
# Template único
gofence vulns https://alvo.com/ -t template.yaml

# Diretório com vários templates
gofence vulns https://alvo.com/ -t ./templates/
```

Exemplo de template:

```yaml
id: exemplo-sqli
name: Detecta SQLi em /login
requests:
  - method: GET
    path: /login?user=admin'--
matchers:
  - type: status
    status: 500
  - type: word
    words: "SQL syntax"
```

Matchers suportados: `status` | `regex` | `word`.

---

## Pilar 3 — Exploração e Helpers

### `payload` — Gerador de payloads

```bash
# Reverse shell em Bash
gofence payload --type bash --ip 10.0.0.1 --port 4444

# Reverse shell em Python
gofence payload --type python --ip 10.0.0.1 --port 4444

# Bind shell (escuta no alvo)
gofence payload --type nc --port 9999 --bind
```

Tipos: `nc` | `python` | `bash` | `perl` | `powershell`.
O payload é impresso no STDOUT (cole no alvo).

### `listen` — Multi-handler

```bash
# Escutar reversas na porta 4444 (TCP)
gofence listen 4444

# UDP
gofence listen --proto udp 4444
```

- Aceita múltiplas sessões simultâneas (gerenciadas em `sync.Map`)
- Decodifica payloads Base64/XOR na recepção
- Log de novas sessões no STDERR

### `brute` — Engine de brute force

```bash
# SSH
gofence brute ssh 10.0.0.5 -u admin -w senhas.txt

# HTTP Basic
gofence brute http https://alvo.com/login -u admin -w senhas.txt

# FTP
gofence brute ftp 10.0.0.5 -u admin -w senhas.txt

# Desativar proteção contra lockout (só em alvos sem rate limit)
gofence brute ssh 10.0.0.5 -u admin -w senhas.txt --no-backoff
```

> Backoff exponencial após 5 falhas (previne lockout do alvo). Use
> `--no-backoff` apenas quando o alvo não tiver proteção.

---

## Pilar 4 — Escopo e Gestão de Dados

### `workspace` — Workspaces e escopo

```bash
# Criar workspace para um engajamento
gofence workspace new "Cliente X"

# Listar workspaces
gofence workspace list

# Adicionar CIDR permitido ao escopo
gofence workspace scope 1 10.0.0.0/8
```

O **ScopeGuard** consulta a tabela `scope` do workspace ativo antes de qualquer
operação de rede. IPs fora do CIDR permitido são bloqueados.

### Banco de dados (SQLite)

Tabelas: `workspaces`, `scope`, `hosts`, `ports`, `findings`.
Local padrão: `~/.gofence/gofence.db` (configurável via `--db`).

```bash
# Usar banco específico
gofence --db /path/to/engajamento.db dns alvo.com -w wl.txt
```

**Soft delete:** workspaces têm coluna `deleted_at` (mantém histórico para
auditoria).

---

## Pilar 5 — UX e Arquitetura

### Modo Interativo (TUI)

Se executado em um terminal (stdout é TTY) sem `--no-tui`, abre dashboard
Bubbletea com painéis: **HOSTS**, **PORTS**, **SESSIONS**, **LOG**.

```bash
gofence            # abre TUI
gofence --no-tui   # força headless
```

### Modo Headless / Pipeline

STDOUT reservado para dados puros (JSON quando detectado não-TTY ou `--json`);
STDERR para logs, barras de progresso e alertas.

```bash
# Pipe: DNS → Port → Fuzz
gofence dns alvo.com -w sub.txt | gofence port | gofence fuzz web

# Integração com jq
gofence dns alvo.com -w sub.txt --json | jq '.subdomains'
```

### Rate Limiting (evasão)

| Perfil | Taxa |
|--------|------|
| `sneaky` | 1 req/s |
| `normal` | 50 req/s |
| `aggressive` | sem limite (limitado pelo SO) |

```bash
gofence --rate sneaky dns alvo.com -w wl.txt
```

---

## Exemplos de fluxo (pipeline)

### Reconhecimento completo de um alvo

```bash
# 1. Descobrir subdomínios
gofence dns alvo.com -w subdomains.txt -w /dev/stdin <<< "www api admin dev"

# 2. Consultar OSINT
gofence osint alvo.com --provider all

# 3. Varrer portas dos IPs descobertos
gofence port 10.0.0.0/24 --top 1000

# 4. Analisar TLS dos serviços web
gofence tls alvo.com:443 --strict

# 5. Fuzar diretórios
gofence fuzz web https://alvo.com/FUZZ -w paths.txt

# 6. Rodar templates de vuln
gofence vulns https://alvo.com/ -t ./nuclei-templates/
```

### Setup de exploração (reverse shell)

```bash
# Terminal 1: iniciar handler
gofence listen 4444

# Terminal 2: gerar payload e executar no alvo
gofence payload --type python --ip 10.0.0.1 --port 4444
```

---

## Desenvolvimento e testes

### Estrutura

```
gofence/
├── cmd/            # Comandos Cobra (entry points)
├── internal/
│   ├── recon/      # DNS, OSINT, port scan
│   ├── surface/    # Fuzzer, TLS, crawler, vuln templates
│   ├── exploit/    # Payloads, handler, brute force
│   ├── data/       # SQLite, models, ScopeGuard
│   ├── ux/         # TUI, headless, rate limiter
│   └── config/     # Viper config
├── pkg/httpclient/ # Cliente HTTP customizado
└── main.go
```

### Rodar testes

```bash
go test ./...
```

### Auditoria da especificação (onp-spec)

Este projeto usa o fluxo **onp-spec** (spec-anchored). A especificação vive em
`.spec/features/gofence-cli/` e é auditada mecanicamente contra o código:

```bash
# Rodar os testes e gravar prova por critério de aceite
node <dir-skill>/scripts/onp-spec.mjs verify gofence-cli

# Auditar (gate final — exit 0 = alinhado)
node <dir-skill>/scripts/onp-spec.mjs audit --ci
```

---

## Observações de segurança

- O ScopeGuard é uma **camada de proteção**, não uma desculpa: confirme sempre
  o escopo por escrito antes de qualquer teste.
- O binário ignora certificados TLS inválidos por padrão (`tls_skip_verify:
  true`) — adequado para lab, mas revise em produção.
- Nenhum exploit zero-day ou payload ofensivo é embutido; o `payload` gera
  apenas one-liners de shell reverso/bind para operações autorizadas.

---

## Licença

Uso restrito a testes de segurança autorizados.
