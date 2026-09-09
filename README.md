# gofence

Ferramenta CLI de segurança ofensiva (pentest) escrita em Go — binário único,
pure Go (sem CGO), focada em reconhecimento, mapeamento de superfície e
exploração. Arquitetura modular em 5 pilares, com armazenamento local em
SQLite, wordlists/templates embutidos, modos interativo (TUI) e headless
(pipeline UNIX) e persistência de achados por workspace.

> ⚠️ **Uso autorizado apenas.** Esta ferramenta destina-se a testes de intrusão
> com autorização explícita (escopo contratado). O módulo ScopeGuard bloqueia
> qualquer operação de rede fora do CIDR declarado no workspace.

---

## Índice

- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Visão geral dos comandos](#visão-geral-dos-comandos)
- [Flags globais](#flags-globais)
- [Configuração](#configuração)
- [Referência de comandos](#referência-de-comandos)
- [Pilar 1 — Coleta e Recon](#pilar-1--coleta-e-recon)
- [Pilar 2 — Superfície e Vulnerabilidades](#pilar-2--superfície-e-vulnerabilidades)
- [Pilar 3 — Exploração e Helpers](#pilar-3--exploração-e-helpers)
- [Pilar 4 — Escopo e Gestão de Dados](#pilar-4--escopo-e-gestão-de-dados)
- [Pilar 5 — UX e Arquitetura](#pilar-5--ux-e-arquitetura)
- [Exemplos de fluxo (pipeline)](#exemplos-de-fluxo-pipeline)
- [Banco de dados (SQLite)](#banco-de-dados-sqlite)
- [Desenvolvimento e testes](#desenvolvimento-e-testes)
- [Observações de segurança](#observações-de-segurança)

---

## Instalação

### Pré-requisitos

- Go 1.25+ (go.mod exige 1.25.0)
- Acesso de rede conforme o alvo autorizado

### Build a partir do código-fonte

```bash
git clone <repo> gofence
cd gofence

# Build simples
go build -o gofence .

# Build estático portátil (recomendado; sem CGO, qualquer Linux amd64/arm64)
make static
# equivalente a: CGO_ENABLED=0 go build -ldflags '-s -w' -o gofence .

# Build com versão/commit injetados (mostrados no gofence --version)
make build
```

> O projeto usa `modernc.org/sqlite` (pure Go) — **nenhuma dependência de CGO**.

### Verificar instalação

```bash
./gofence --help
./gofence --version    # gofence version <tag> (commit <sha>)
```

---

## Início rápido

Todo comando de rede exige um workspace com escopo (fail-closed):

```bash
# 1. Criar e ativar workspace
gofence workspace new "Cliente X"
gofence workspace scope "Cliente X" 10.0.0.0/8
gofence workspace set-active "Cliente X"

# 2. Recon
gofence dns alvo.com                       # subdomínios (wordlist embutida)
gofence port 10.0.0.0/24 --top 1000        # portas

# 3. Superfície
gofence tls alvo.com:443                   # certificado/cifras (JSON)
gofence fuzz https://alvo.com/FUZZ         # diretórios (wordlist embutida)

# 4. Relatório
gofence report --format md --out relatorio.md
```

---

## Visão geral dos comandos

| Comando | Descrição |
|---------|-----------|
| `gofence` (sem args) | Abre a TUI (se stdout for um terminal) |
| `gofence --version` | Versão e commit (injetados via ldflags) |
| `gofence dns <alvo>` | Brute-force de subdomínios e transferência de zona (AXFR) |
| `gofence subdomains <domain>` | Resolução de subdomínios via wordlist (estilo gobuster dns) |
| `gofence osint <alvo>` | Consulta Shodan, Censys, SecurityTrails + providers keyless |
| `gofence port <ip/cidr>` | Varredura TCP/UDP com banners, NSE-lite, SYN e XML |
| `gofence fuzz <url>` | Fuzzer web de caminhos, headers e POST |
| `gofence s3 [placeholder]` | Enumeração de buckets S3 (existência + visibilidade) |
| `gofence vhost <url>` | Descoberta de virtual hosts via Host header |
| `gofence tls <host:porta>` | Análise de certificado TLS e cifras |
| `gofence crawl <url>` | Crawler com detecção de segredos |
| `gofence vulns <alvo>` | Templates de vulnerabilidade (formato Nuclei) |
| `gofence payload` | Gera payloads de reverse/bind shell |
| `gofence listen [porta]` | Multi-handler interativo para conexões reversas |
| `gofence brute <ssh\|http\|ftp>` | Brute force de dicionário |
| `gofence workspace` | Gerencia workspaces, escopo e workspace ativo |
| `gofence report` | Agrega hosts/ports/findings em Markdown/JSON |

📖 **Documentação detalhada de cada comando** (flags, exemplos, comportamento
de saída e persistência): [docs/COMMANDS.md](./docs/COMMANDS.md)

---

## Flags globais

Aplicam-se a todos os comandos. Precedência: **flag CLI > env `GOFENCE_*` >
`~/.gofence/config.yaml` > padrões**.

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--config <arquivo>` | `~/.gofence/config.yaml` | Arquivo de configuração YAML |
| `--no-tui` | `false` | Força modo headless (desativa TUI) |
| `--json` | `false` | Força saída JSON no STDOUT |
| `--rate <perfil>` | config (`normal`) | `sneaky`\|`normal`\|`aggressive` |
| `--concurrency <n>` | config (`100`) | Máximo de goroutines simultâneas |
| `--db <caminho>` | config (`~/.gofence/gofence.db`) | Caminho do banco SQLite |
| `--workspace <nome>` | _(workspace ativo salvo)_ | Workspace para persistência |

> 🔒 **TLS:** a verificação de certificado vem **ativada** por padrão
> (`tls_skip_verify: false`). Para alvos com TLS quebrado/self-signed, defina
> `GOFENCE_TLS_SKIP_VERIFY=true` ou `tls_skip_verify: true` no config.

Env vars disponíveis: `GOFENCE_SHODAN_KEY`, `GOFENCE_CENSYS_ID`,
`GOFENCE_CENSYS_SECRET`, `GOFENCE_SECURITYTRAILS_KEY`, `GOFENCE_RATE_PROFILE`,
`GOFENCE_CONCURRENCY`, `GOFENCE_DB_PATH`, `GOFENCE_NO_TUI`,
`GOFENCE_JSON_OUTPUT`, `GOFENCE_WORDLIST_PATH`, `GOFENCE_PROXY_URL`,
`GOFENCE_TLS_SKIP_VERIFY`.

---

## Configuração

Crie `~/.gofence/config.yaml` (ou use variáveis de ambiente `GOFENCE_*`):

```yaml
shodan_key: "SUA_CHAVE_SHODAN"
censys_id: "SEU_CENSYS_ID"
censys_secret: "SEU_CENSYS_SECRET"
securitytrails_key: "SUA_CHAVE_SECURITYTRAILS"
rate_profile: "normal"        # sneaky | normal | aggressive
concurrency: 100
db_path: "~/.gofence/gofence.db"
proxy_url: ""                 # proxy HTTP para todos os módulos web
tls_skip_verify: false        # padrão seguro; true só para alvos com TLS quebrado
```

Ou via ambiente:

```bash
export GOFENCE_SHODAN_KEY="SUA_CHAVE_SHODAN"
export GOFENCE_PROXY_URL="http://127.0.0.1:8080"   #roteia fuzz/crawl/vulns via Burp/ZAP
export GOFENCE_TLS_SKIP_VERIFY=true                #lab/self-signed
```

> **Segurança:** chaves nunca devem ser hard-coded. Use env vars ou arquivo de
> configuração fora do repo.

---

## Referência de comandos

A documentação completa de cada comando — flags, exemplos, formato de saída e
comportamento de persistência — está em **[docs/COMMANDS.md](./docs/COMMANDS.md)**.

Resumo por pilar:

| Pilar | Comandos |
|-------|----------|
| Recon | `dns`, `subdomains`, `osint`, `port` |
| Superfície | `fuzz`, `s3`, `vhost`, `tls`, `crawl`, `vulns` |
| Exploração | `payload`, `listen`, `brute` |
| Dados | `workspace`, `report` |

---

## Pilar 1 — Coleta e Recon

### `dns` — Descoberta de subdomínios

```bash
# Brute-force com wordlist embutida (sem -w usa subdomains.txt interno)
gofence dns alvo.com

# Brute-force de subdomínios com wordlist própria
gofence dns alvo.com -w /caminho/wordlist.txt

# Limitar concorrência
gofence dns alvo.com -w wordlist.txt --concurrency 500

# Transferência de zona (AXFR)
gofence dns alvo.com --axfr --nameserver ns1.alvo.com
```

Saída (STDOUT, uma por linha): `subdominio IP`. AXFR imprime JSON.
Quando há workspace ativo, os subdomínios são persistidos como findings
(`info/subdomain`) e o total vai para o STDERR.

### `subdomains` — Resolução dedicada de subdomínios

Equivalente ao `fuzz --dns`, como comando próprio (estilo `gobuster dns`),
com detecção de wildcard DNS e escopo checado por IP resolvido:

```bash
gofence subdomains alvo.com -w subs.txt --nameserver 1.1.1.1:53
```

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

# CIDR inteiro — expandido host a host
gofence port 10.0.0.0/24 --top 1000

# Lista de alvos em arquivo (-iL estilo nmap; CIDRs do arquivo também são expandidos)
gofence port -iL alvos.txt --top 1000

# Ping sweep antes de varrer (descobre hosts vivos)
gofence port 10.0.0.0/24 --ping-sweep

# Retries e timeout por porta
gofence port 10.0.0.5 --ports 22,80 --retries 2 --timeout 3

# SYN scan stealth — exige root/CAP_NET_RAW; sem privilégio, erro claro
gofence port 10.0.0.5 --syn --ports 22,80,443

# Palpite de SO por sinais TCP (TTL/janela heurísticos por serviço)
gofence port 10.0.0.5 --ports 22,3389 --os-guess

# Saída XML compatível com nmap -oX (Metasploit/Faraday) — shorthand estilo nmap
gofence port 10.0.0.5 --top 1000 -oX scan.xml
```

A detecção de serviço/versão é automática: banner grabbing na porta aberta
(SSH, HTTP, FTP, SMTP...) preenche `Service` e `Version`; sem banner, cai no
mapa estático. Scripts NSE-lite registrados em Go rodam por serviço
detectado (SSH/DNS/SMTP) e seus resultados aparecem na saída.

Portas abertas são persistidas no workspace ativo (tabela `ports`).

> Toda operação passa pelo **ScopeGuard** (fail-closed) — sem workspace ativo
> ou com alvo fora do escopo, o comando é recusado com log
> `Out-of-Scope Blocked` no STDERR, sem enviar pacote à rede.

---

## Pilar 2 — Superfície e Vulnerabilidades

### `fuzz` — Fuzzer web de alta performance

Lê a wordlist como **stream** (não carrega tudo na RAM — suporta wordlists
gigantes). Sem `-w`, usa a wordlist embutida `paths.txt`.

```bash
# Fuzzing de caminhos (wordlist embutida)
gofence fuzz https://alvo.com/FUZZ

# Fuzzing de caminhos com wordlist própria
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt

# Fuzzing de cabeçalho
gofence fuzz https://alvo.com/ -w hosts.txt --header "Host: FUZZ"

# Fuzzing de dados POST
gofence fuzz https://alvo.com/login -w passwords.txt --data "user=admin&pass=FUZZ"

# Suprimir status codes ruidosos e desativar parada por WAF
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt --ignore-status 403,429 --waf-backoff=false

# Whitelist de status e filtro por tamanho de resposta
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt --status-codes 200,301 --exclude-length 404,500

# Recursão em diretórios descobertos (BFS, profundidade limitada)
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt --recursive --depth 3

# Extensões automáticas (-x): testa index.php, index.html...
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt -x php,html

# Seeds de robots.txt/sitemap.xml
gofence fuzz https://alvo.com/FUZZ --robots
gofence fuzz https://alvo.com/FUZZ --sitemap

# Resume: salvar estado e continuar depois
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt -o estado.json
gofence fuzz https://alvo.com/FUZZ --resume estado.json

# Auth, cookie e User-Agent
gofence fuzz https://alvo.com/FUZZ -w wordlist.txt --auth admin:secret --cookie "session=abc" --user-agent "gofence/1.0"
```

Imprime no STDOUT apenas respostas com status ≠ 404: `[status] url (size: N)`.
A detecção de página curinga (wildcard) é automática: uma requisição de
referência com path aleatório é feita antes da onda, e respostas com mesmo
status+tamanho são descartadas com aviso no STDERR. Com `--waf-backoff`
(padrão), ao detectar WAF a onda para e um aviso `WAF wall hit (...)` vai
para o STDERR com sugestão de `--rate sneaky`. Erros de conexão transientes
são retentados (`--retries`, padrão 2). Progresso/ETA aparecem no STDERR
(`--progress`, padrão ligado; STDOUT permanece puro para pipelines).
Achados são persistidos no workspace ativo (`info/fuzz <status>`).

### `s3` — Enumeração de buckets S3

```bash
gofence s3 probe -w buckets.txt
gofence s3 probe -w buckets.txt --json | jq 'map(select(.private))'
```

`200/301` = existe (público), `403` = existe (privado), `404` = não existe.
Buckets expostos persistem como `medium/open s3 bucket`.

### `vhost` — Descoberta de virtual hosts

```bash
gofence vhost https://alvo.com/ -w vhosts.txt
```

Fuzza o header `Host` e descarta respostas idênticas à base (vhost default).

### `tls` — Análise de certificado

```bash
gofence tls alvo.com:443
gofence tls alvo.com            # porta 443 implícita
gofence tls 10.0.0.5:8443 --strict   # sonda protocolos legados e alerta se TLS < 1.2
```

Saída JSON: subject, issuer, validade, fingerprint SHA-256, cifras, protocolos.
O achado é persistido no workspace ativo (`info` ou `medium` se grade C).

### `crawl` — Crawler baseado em AST

```bash
gofence crawl https://alvo.com/ --depth 3
```

- Extrai links (BFS até a profundidade configurada)
- Detecta segredos (JWT, AWS keys, API keys) — alertas no **STDERR**
- Ignora `robots.txt` (decisão deliberada para pentest)
- Segredos são persistidos no workspace ativo (`high` para AWS_KEY/AWS_SECRET/JWT,
  `medium` para os demais); respeita `--rate` e detector de WAF

### `vulns` — Templates de vulnerabilidade

Formato compatível com **Nuclei** (YAML com `requests[]` e `matchers[]`).
Sem `-t`, usa os templates embutidos (`exposed-aws.yaml`, `exposed-git.yaml`).

```bash
# Templates embutidos
gofence vulns https://alvo.com/

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

Ao final imprime `SUMMARY: templates=N executed=N matched=N failed=N` no STDOUT.
Matches são persistidos no workspace ativo como `high/vuln <id>`.

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
gofence listen --proto udp 5555
```

- Aceita múltiplas sessões simultâneas (gerenciadas em `sync.Map`)
- Decodifica payloads Base64 na recepção
- Log de novas sessões no STDOUT

**Console interativo** (stdin é TTY): `sessions` lista as conexões ativas,
`send <id> <dados>` envia dados para uma sessão e `kill <id>` encerra uma.
`Ctrl+C` faz shutdown gracioso (fecha listener e sessões). Em pipe, roda em
modo servidor puro.

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

Credenciais encontradas são persistidas no workspace ativo
(`high/brute <service> credential`).

---

## Pilar 4 — Escopo e Gestão de Dados

### `workspace` — Workspaces e escopo

```bash
# Criar workspace para um engajamento
gofence workspace new "Cliente X"

# Listar workspaces
gofence workspace list

# Marcar workspace como ativo para os scans
gofence workspace set-active "Cliente X"

# Adicionar CIDR permitido ao escopo (por id ou nome)
gofence workspace scope 1 10.0.0.0/8
gofence workspace scope "Cliente X" 10.0.0.0/8

# Encerrar workspace (soft delete: some do list, mantém histórico)
gofence workspace delete "Cliente X"
```

O **ScopeGuard** é fail-closed: todo comando de rede exige workspace ativo
com escopo cadastrado. Sem workspace, com escopo vazio ou com alvo fora dos
CIDRs, o comando recusa com erro — alvos fora do escopo geram log
`Out-of-Scope Blocked` no STDERR sem nenhum pacote enviado.

O workspace ativo é resolvido nesta ordem: flag `--workspace <nome>` >
valor salvo em KV (`workspace set-active`).

### `report` — Relatório do workspace

```bash
# Markdown no STDOUT (workspace ativo)
gofence report

# JSON no STDOUT
gofence report --format json

# Escrever em arquivo, de outro banco / workspace
gofence report --format md --out relatorio.md
gofence --db /path/to/engajamento.db --workspace "Cliente X" report --format json
```

Agrega `hosts` + `ports` + `findings` do workspace ativo.

### Banco de dados (SQLite)

Tabelas: `workspaces`, `scope`, `hosts`, `ports`, `findings`, `kv`
(`kv` guarda `active_workspace`).
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
STDERR para logs, barras de progresso e alertas (inclui `persisted N ...`
e avisos de WAF).

Comandos com alvo (`dns`, `subdomains`, `osint`, `port`, `fuzz`, `tls`,
`crawl`, `vulns`, `brute`) aceitam o alvo via pipe quando o argumento é
omitido: vale a primeira linha do stdin (primeiro campo), e linhas extras
geram aviso no STDERR. O argumento explícito tem prioridade; sem nenhum dos
dois, o comando pede o alvo e sai com erro. A checagem de escopo vale para
alvos do pipe.

```bash
# Pipe direto: DNS → Port (primeiro alvo do stdin)
gofence dns alvo.com -w sub.txt | gofence port --top 100

# TLS sempre sai em JSON — bom para jq
gofence tls alvo.com:443 | jq '.subject'
```

### Cancelamento (Ctrl+C)

Todos os comandos de longa duração escutam SIGINT/SIGTERM: a onda para de
enfileirar trabalho, as requisições em voo terminam e os recursos (temp
files, estado de resume) são liberados pelos `defer` — em vez de morrer no
meio do scan.

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
# 0. Preparar workspace e escopo (obrigatório: comandos de rede recusam sem isso)
gofence workspace new "Cliente X"
gofence workspace scope "Cliente X" 10.0.0.0/8
gofence workspace set-active "Cliente X"

# 1. Descobrir subdomínios (wordlist embutida se omitir -w)
gofence dns alvo.com -w subdomains.txt

# 2. Consultar OSINT
gofence osint alvo.com --provider all

# 3. Varrer portas dos IPs descobertos
gofence port 10.0.0.0/24 --top 1000

# 4. Analisar TLS dos serviços web
gofence tls alvo.com:443 --strict

# 5. Fuzar diretórios
gofence fuzz https://alvo.com/FUZZ -w paths.txt

# 6. Rodar templates de vuln (embutidos se omitir -t)
gofence vulns https://alvo.com/ -t ./nuclei-templates/

# 7. Gerar relatório do workspace ativo
gofence workspace set-active "Cliente X"
gofence report --format md --out relatorio.md
```

### Setup de exploração (reverse shell)

```bash
# Terminal 1: iniciar handler
gofence listen 4444

# Terminal 2: gerar payload e executar no alvo
gofence payload --type python --ip 10.0.0.1 --port 4444
```

### Enumeração de cloud

```bash
gofence s3 probe -w buckets.txt --json | jq 'map(select(.private == true))'
gofence vhost https://alvo.com/ -w vhosts.txt --json
```

---

## Desenvolvimento e testes

### Estrutura

```
gofence/
├── cmd/            # Comandos Cobra (entry points) + helpers.go/report.go
├── docs/           # Referência de comandos (COMMANDS.md)
├── internal/
│   ├── assets/     # Wordlists e templates embutidos (go:embed)
│   ├── recon/      # DNS, OSINT, port scan
│   ├── surface/    # Fuzzer, TLS, crawler, vuln templates
│   ├── exploit/    # Payloads, handler, brute force
│   ├── data/       # SQLite, models, ScopeGuard
│   ├── ux/         # TUI, headless, rate limiter, WAF detector
│   └── config/     # Viper config
├── pkg/httpclient/ # Cliente HTTP customizado
└── main.go
```

### Rodar testes

```bash
go test ./...                                  # suíte completa
go test -race ./...                            # com detector de data race
go test ./internal/surface                     # pacote único
go test -v ./internal/surface -run TestFuzzer  # teste focado
```

`make vet` roda `go vet ./...` (deve estar limpo — endereços IPv6 sempre via
`net.JoinHostPort`). `make static` produz o binário portátil sem CGO.

### CI

GitHub Actions (`.github/workflows/ci.yml`) roda em todo push/PR:
`go vet`, `go test -race`, build estático CGO-free e smoke test (`--version`).

### Auditoria da especificação (onp-spec)

Este projeto usa o fluxo **onp-spec** (spec-anchored). As especificações vivem em
`.spec/features/` (`gofence-cli`, `scope-enforcement`, `pipeline-stdin`,
`workspace-delete`) e são auditadas mecanicamente contra o código:

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
- A verificação de certificado TLS vem **ativada** por padrão; desative
  (`GOFENCE_TLS_SKIP_VERIFY=true`) apenas em lab ou alvos com TLS quebrado.
- Nenhum exploit zero-day ou payload ofensivo é embutido; o `payload` gera
  apenas one-liners de shell reverso/bind para operações autorizadas.

---

## Licença

GPL-3.0-or-later — veja o arquivo [LICENSE](./LICENSE).

> ⚠️ **Uso autorizado apenas.** Independentemente da licença de código,
> esta ferramenta destina-se a testes de intrusão com autorização
> explícita (escopo contratado).
