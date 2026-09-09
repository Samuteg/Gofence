# Referência de Comandos — gofence

Guia de uso de cada comando, com flags, exemplos e comportamento de saída.

> ⚠️ **Uso autorizado apenas.** Todos os comandos de rede passam pelo
> **ScopeGuard** (fail-closed): sem workspace ativo com escopo cadastrado, ou
> com alvo fora dos CIDRs declarados, o comando recusa com log
> `Out-of-Scope Blocked` no STDERR — nenhum pacote é enviado.

**Convenções de saída** (disciplina UNIX):

- **STDOUT** — dados puros (resultados, JSON) para pipelines
- **STDERR** — status, progresso, avisos de WAF e contadores de persistência

**Alvo via pipe:** todos os comandos com alvo (`dns`, `subdomains`, `osint`,
`port`, `fuzz`, `s3`, `vhost`, `tls`, `crawl`, `vulns`, `brute`) aceitam o
alvo pela primeira linha do stdin quando o argumento posicional é omitido.
Argumento explícito tem prioridade; linhas extras do pipe são ignoradas com
aviso no STDERR.

---

## Índice

- [Flags globais](#flags-globais)
- [dns](#dns--dns-brute-force-e-axfr)
- [subdomains](#subdomains--resolução-de-subdomínios)
- [osint](#osint--inteligência-de-fontes-externas)
- [port](#port--varredura-de-portas)
- [fuzz](#fuzz--fuzzer-web)
- [s3](#s3--enumeração-de-buckets-s3)
- [vhost](#vhost--descoberta-de-virtual-hosts)
- [tls](#tls--análise-de-certificado)
- [crawl](#crawl--crawler-com-detecção-de-segredos)
- [vulns](#vulns--templates-de-vulnerabilidade)
- [payload](#payload--gerador-de-payloads)
- [listen](#listen--multi-handler)
- [brute](#brute--brute-force-de-dicionário)
- [workspace](#workspace--workspaces-e-escopo)
- [report](#report--relatório-do-workspace)

---

## Flags globais

Aplicam a todos os comandos. Precedência: **flag CLI > env `GOFENCE_*` >
config.yaml > padrão**.

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--config <arquivo>` | `~/.gofence/config.yaml` | Arquivo de configuração YAML |
| `--no-tui` | `false` | Força modo headless |
| `--json` | `false` | Força saída JSON no STDOUT |
| `--rate <perfil>` | config (`normal`) | `sneaky` (1 req/s) \| `normal` (50 req/s) \| `aggressive` (sem limite) |
| `--concurrency <n>` | config (`100`) | Máximo de goroutines simultâneas |
| `--db <caminho>` | config (`~/.gofence/gofence.db`) | Caminho do banco SQLite |
| `--workspace <nome>` | _(workspace ativo salvo)_ | Workspace para persistência |

Ver `~/.gofence/config.yaml` e env vars em [Configuração](../README.md#configuração).

---

## `completion` — Autocomplete de shell

Scripts de autocomplete embutidos (via Cobra):

```bash
# Bash (sessão atual)
source <(gofence completion bash)

# Persistir
 gofence completion bash > ~/.local/share/bash-completion/completions/gofence

# zsh / fish / powershell
gofence completion zsh
gofence completion fish
gofence completion powershell
```

---

## `dns` — DNS brute-force e AXFR

Brute-force de subdomínios e transferência de zona.

```bash
# Brute-force com wordlist embutida (subdomains.txt interno)
gofence dns alvo.com

# Com wordlist própria
gofence dns alvo.com -w /caminho/wordlist.txt

# Concorrência alta
gofence dns alvo.com -w wl.txt --concurrency 500

# Transferência de zona
gofence dns alvo.com --axfr --nameserver ns1.alvo.com
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-w, --wordlist` | embutida | Wordlist de subdomínios |
| `--axfr` | `false` | Tenta transferência de zona |
| `--nameserver` | `8.8.8.8` | Nameserver para AXFR |

**Saída:** `subdominio IP` por linha; AXFR imprime JSON de registros.
**Persistência:** subdomínios como `info/subdomain`.

---

## `subdomains` — Resolução de subdomínios

Modo dedicado (estilo `gobuster dns`) para resolver subdomínios de uma
wordlist via `recon.Resolver`, com detecção de wildcard DNS (catch-all).
Equivalente ao `fuzz --dns`, com escopo e persistência próprios.

```bash
# Wordlist embutida
gofence subdomains alvo.com

# Wordlist própria + nameserver específico
gofence subdomains alvo.com -w subs.txt --nameserver 1.1.1.1:53
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-w, --wordlist` | embutida | Wordlist de subdomínios |
| `--nameserver` | `8.8.8.8:53` | Resolver DNS (host:porta) |

**Escopo:** o domínio e cada IP resolvido são checados (fail-closed).
**Saída:** `subdominio IP` por linha; com `--json`, array com
`subdomain`/`ip`.
**Persistência:** `info/subdomain`.

---

## `osint` — Inteligência de fontes externas

```bash
# Todos os providers (keyless primeiro: crtsh, hackertarget, whois)
gofence osint alvo.com --provider all

# Apenas Shodan (exige GOFENCE_SHODAN_KEY)
gofence osint alvo.com --provider shodan

# JSON para jq
gofence osint 1.2.3.4 --json | jq '.[].data'
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--provider` | `all` | `crtsh`\|`hackertarget`\|`whois`\|`shodan`\|`censys`\|`securitytrails`\|`all` (keyless: crtsh, hackertarget, whois) |

Retry com backoff em HTTP 429. Resultados persistidos como `info/osint <provider>`.

---

## `port` — Varredura de portas

```bash
# Top 1000 TCP
gofence port 10.0.0.5 --top 1000

# Portas específicas
gofence port 10.0.0.5 --ports 22,80,443,8080

# UDP
gofence port 10.0.0.5 --udp --top 100

# CIDR inteiro
gofence port 10.0.0.0/24 --top 1000

# Lista de alvos em arquivo (estilo nmap -iL)
gofence port -iL alvos.txt --top 1000

# Ping sweep antes de varrer
gofence port 10.0.0.0/24 --ping-sweep

# SYN scan (exige root/CAP_NET_RAW)
gofence port 10.0.0.5 --syn --ports 22,80,443

# Palpite de SO
gofence port 10.0.0.5 --ports 22,3389 --os-guess

# XML compatível com nmap -oX
gofence port 10.0.0.5 --top 1000 -oX scan.xml

# JSON para jq
gofence port 10.0.0.5 --top 100 --json | jq 'map(select(.state=="open"))'
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--ports` | — | Lista de portas (vírgula) |
| `--top` | `1000` | Top N portas comuns |
| `--udp` | `false` | Varre UDP |
| `--iL` | — | Arquivo com alvos por linha (CIDRs expandidos) |
| `--ping-sweep` | `false` | Descobre hosts vivos antes |
| `--retries` | `0` | Tentativas extras por porta |
| `--timeout` | `2` | Timeout por porta (segundos) |
| `--oX` | — | XML estilo nmap |
| `--syn` | `false` | SYN scan stealth |
| `--os-guess` | `false` | Palpite de SO (TTL/janela) |

Detecção de serviço/versão automática por banner grabbing (SSH, HTTP, SMTP...).
Scripts NSE-lite registrados rodam por serviço. Portas abertas persistem na
tabela `ports`.

---

## `fuzz` — Fuzzer web

Wordlist em **stream** (suporta listas gigantes). Sem `-w`, usa `paths.txt`
embutida. Detecção de wildcard automática; `--waf-backoff` para a onda ao
detectar WAF.

```bash
# Caminhos
gofence fuzz https://alvo.com/FUZZ

# Cabeçalho / POST
gofence fuzz https://alvo.com/ -w hosts.txt --header "Host: FUZZ"
gofence fuzz https://alvo.com/login -w pw.txt --data "user=admin&pass=FUZZ"

# Filtros
gofence fuzz https://alvo.com/FUZZ --ignore-status 403,429 --status-codes 200,301 --exclude-length 404,500

# Recursão BFS + extensões
gofence fuzz https://alvo.com/FUZZ --recursive --depth 3 -x php,html

# Resume
gofence fuzz https://alvo.com/FUZZ -o estado.json
gofence fuzz https://alvo.com/FUZZ --resume estado.json

# Auth
gofence fuzz https://alvo.com/FUZZ --auth admin:secret --bearer TOKEN --ntlm user:pass

# Modos legados (preferir os comandos dedicados)
gofence fuzz https://alvo.com/ -w hosts.txt --vhost        # → gofence vhost
gofence fuzz --s3 -w buckets.txt                           # → gofence s3
gofence fuzz --dns alvo.com -w subs.txt                    # → gofence subdomains
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-w, --wordlist` | embutida | Wordlist (marcador `FUZZ`) |
| `--header` | — | Header a fuzzar (`Host: FUZZ`) |
| `--data` | — | Body POST com `FUZZ` |
| `--ignore-status` | — | Status a suprimir |
| `--status-codes` | — | Mostrar só estes status |
| `--exclude-length` | — | Suprimir por tamanho do body |
| `--recursive` / `--depth` | `false` / `3` | Recursão BFS em diretórios |
| `-x, --x` | — | Extensões (`php,html`) |
| `--robots` / `--sitemap` | `false` | Semeia wordlist de robots/sitemap |
| `-o, --output` / `--resume` | — | Salva/retoma sessão |
| `--auth` / `--bearer` / `--ntlm` / `--cookie` / `--user-agent` | — | Credenciais/headers |
| `--retries` | `2` | Retries de transporte |
| `--waf-backoff` | `true` | Para a onda ao detectar WAF |
| `--progress` | `true` | Progresso no STDERR |
| `--vhost` / `--s3` / `--dns` | — | Modos dedicados (ver comandos próprios) |

**Saída:** `[status] url (size: N)` no STDOUT.
**Persistência:** `info/fuzz <status>`.

---

## `s3` — Enumeração de buckets S3

Testa cada nome da wordlist como bucket S3 (`<bucket>.s3.amazonaws.com`).
`200/301` = existe (público); `403` = existe (privado); `404` = não existe.

```bash
# Wordlist embutida
gofence s3 probe

# Wordlist própria + JSON
gofence s3 probe -w buckets.txt --json | jq 'map(select(.private))'
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-w, --wordlist` | embutida | Nomes de bucket (um por linha) |

O argumento posicional é placeholder (nomes vêm da wordlist).
**Saída:** `[status] bucket (exists|exists/private)`; com `--json`, array de
objetos `bucket`/`url`/`status_code`/`exists`/`private`.
**Persistência:** buckets expostos como `medium/open s3 bucket`.

---

## `vhost` — Descoberta de virtual hosts

Fuzza o header `Host` e descarta respostas idênticas à base (vhost default).

```bash
gofence vhost https://alvo.com/ -w vhosts.txt

# JSON
gofence vhost https://alvo.com/ -w vhosts.txt --json
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-w, --wordlist` | embutida | Nomes de vhost (um por linha) |

**Saída:** `[status] url (size: N)`; com `--json`, array de `FuzzResult`.
**Persistência:** `info/vhost <status>`.

---

## `tls` — Análise de certificado

```bash
gofence tls alvo.com:443
gofence tls alvo.com              # 443 implícito
gofence tls 10.0.0.5:8443 --strict

# jq direto
gofence tls alvo.com:443 | jq '.grade'
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--strict` | `false` | Sonda protocolos legados; alerta TLS < 1.2 |

**Saída:** JSON (subject, issuer, validade, fingerprint, cifras, protocolos).
Com `--json` suprime a decoração e grava JSON puro.
**Persistência:** `info` ou `medium` (grade C).

---

## `crawl` — Crawler com detecção de segredos

```bash
gofence crawl https://alvo.com/ --depth 3

# JSON (URLs + segredos)
gofence crawl https://alvo.com/ --json | jq '.secrets'
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--depth` | `3` | Profundidade máxima (BFS) |

Extrai links, detecta JWT/AWS keys/API keys; ignora `robots.txt`
(decisão deliberada de pentest). Respeita `--rate` e WAF detector.
**Persistência:** `high` para AWS_KEY/AWS_SECRET/JWT, `medium` para os demais.

---

## `vulns` — Templates de vulnerabilidade

Formato **Nuclei** (YAML com `requests[]`/`matchers[]`). Sem `-t`, usa os
templates embutidos (`exposed-aws.yaml`, `exposed-git.yaml`).

```bash
gofence vulns https://alvo.com/            # embutidos
gofence vulns https://alvo.com/ -t t.yaml  # arquivo único
gofence vulns https://alvo.com/ -t ./tpl/  # diretório
```

Matchers: `status` | `regex` | `word`.

**Saída:** `[MATCH] ...` por match + `SUMMARY: templates=N executed=N matched=N failed=N`;
com `--json`, objeto com `target`, `matches[]` e `summary`.
**Persistência:** matches como `high/vuln <id>`.

---

## `payload` — Gerador de payloads

```bash
gofence payload --type bash --ip 10.0.0.1 --port 4444
gofence payload --type python --ip 10.0.0.1 --port 4444
gofence payload --type nc --port 9999 --bind
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--type` | `nc` | `nc`\|`python`\|`bash`\|`perl`\|`powershell` |
| `--ip` | — | LHOST (reverse) |
| `--port` | — | LPORT |
| `--bind` | `false` | Bind shell em vez de reverse |

Payload one-liner no STDOUT. Nenhum exploit é embutido — apenas one-liners
de shell para operações autorizadas.

---

## `listen` — Multi-handler

Aceita múltiplas conexões reversas simultâneas; decodifica Base64 na recepção.

```bash
gofence listen 4444                 # TCP
gofence listen --proto udp 5555
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--proto` | `tcp` | `tcp`\|`udp` |
| `[porta]` | `4444` | 1–65535 (validada) |

**Console interativo** (quando stdin é TTY):

| Comando | Descrição |
|---------|-----------|
| `sessions` | Lista sessões ativas com origem |
| `send <id> <dados>` | Envia dados para a sessão |
| `kill <id>` | Encerra a sessão |

`Ctrl+C` encerra graciosamente (fecha listener e sessões). Em pipe, roda em
modo servidor puro. O modo **UDP** rastreia cada remetente como uma sessão
distinta e responde via `send <id>`.

---

## `brute` — Brute force de dicionário

```bash
gofence brute ssh 10.0.0.5 -u admin -w senhas.txt
gofence brute http https://alvo.com/admin -u admin -w senhas.txt
gofence brute ftp 10.0.0.5 -u admin -w senhas.txt

# Desativar backoff (só em alvos sem rate limit)
gofence brute ssh 10.0.0.5 -u admin -w senhas.txt --no-backoff
```

| Flag (por subcomando) | Padrão | Descrição |
|------|--------|-----------|
| `-u, --user` | — | Usuário |
| `-w, --wordlist` | — | Wordlist de senhas |
| `--no-backoff` | `false` | Desativa backoff anti-lockout |

Backoff exponencial a cada 5 tentativas por padrão.
**Saída:** `[FOUND] <svc> <target> user=... pass=...`.
**Persistência:** credenciais como `high/brute <svc> credential`.

---

## `workspace` — Workspaces e escopo

```bash
gofence workspace new "Cliente X"              # criar
gofence workspace list                          # listar
gofence workspace set-active "Cliente X"        # ativar
gofence workspace scope "Cliente X" 10.0.0.0/8  # adicionar CIDR
gofence workspace scope 1 10.0.0.0/8            # por id
gofence workspace delete "Cliente X"            # soft delete
```

O workspace ativo é resolvido: flag `--workspace` > KV `active_workspace`.
Sem workspace ativo com escopo, comandos de rede recusam (fail-closed).

---

## `report` — Relatório do workspace

```bash
gofence report                                   # Markdown no STDOUT
gofence report --format json                     # JSON
gofence report --format md --out relatorio.md    # em arquivo
gofence --db /path/engajamento.db --workspace "Cliente X" report --format json
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--format` | `md` | `md`\|`json` |
| `--out` | — | Grava em arquivo em vez do STDOUT |

Agrega `hosts` + `ports` + `findings` do workspace ativo.
