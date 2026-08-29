# Plano de execução — gofence-cli

> gerado por `onp-spec plano` em 2026-08-29 01:40 — NÃO edite à mão;
> mudou tasks.md ou a config? Regenere: `onp-spec plano gofence-cli`

## Resumo — o que vai acontecer

- **20 tarefa(s) pendente(s)**: 20 em 17 faixa(s) paralela(s) + 0 sequencial(is)
- **1 faixa = 1 worktree + 1 branch + 1 janela de contexto limpa** — faixas não compartilham nenhum arquivo entre si
- tudo acontece na branch de trabalho `spec/gofence-cli`; mesclagens voltam para ela; levar para a main é decisão sua

## Faixas e ondas

### Onda 1 — faixa-1 ∥ faixa-2 ∥ faixa-3

#### faixa-1 — branch `spec/gofence-cli-faixa-1` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-1`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-001 | Projeto Go, módulos e dependências | `claude-sonnet-5` | medium | `go.mod`, `go.sum`, `main.go` |
| T-006 | Root command e detecção TUI/headless | `claude-sonnet-5` | medium | `cmd/root.go`, `main.go` |
| T-020 | Integração final e testes | `claude-sonnet-5` | medium | `main.go`, `cmd/*.go` |

#### faixa-2 — branch `spec/gofence-cli-faixa-2` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-2`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-002 | Configuração (Viper) | `claude-sonnet-5` | medium | `internal/config/config.go` |

#### faixa-3 — branch `spec/gofence-cli-faixa-3` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-3`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-003 | HTTP client customizado | `claude-sonnet-5` | medium | `pkg/httpclient/client.go` |

### Onda 2 — faixa-4 ∥ faixa-5 ∥ faixa-6

#### faixa-4 — branch `spec/gofence-cli-faixa-4` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-4`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-004 | ScopeGuard | `claude-sonnet-5` | medium | `internal/data/scope.go`, `internal/data/db.go` |
| T-005 | SQLite schema e models | `claude-sonnet-5` | medium | `internal/data/db.go`, `internal/data/models.go`, `internal/data/workspace.go` |

#### faixa-5 — branch `spec/gofence-cli-faixa-5` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-5`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-007 | Rate limiter | `claude-sonnet-5` | medium | `internal/ux/ratelimit.go` |

#### faixa-6 — branch `spec/gofence-cli-faixa-6` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-6`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-008 | DNS brute-force e AXFR | `claude-sonnet-5` | medium | `internal/recon/dns.go`, `cmd/dns.go` |

### Onda 3 — faixa-7 ∥ faixa-8 ∥ faixa-9

#### faixa-7 — branch `spec/gofence-cli-faixa-7` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-7`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-009 | OSINT clients | `claude-sonnet-5` | medium | `internal/recon/osint.go`, `cmd/osint.go` |

#### faixa-8 — branch `spec/gofence-cli-faixa-8` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-8`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-010 | Port scanner TCP/UDP | `claude-sonnet-5` | medium | `internal/recon/portscan.go`, `cmd/port.go` |

#### faixa-9 — branch `spec/gofence-cli-faixa-9` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-9`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-011 | Fuzzer web | `claude-sonnet-5` | medium | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |

### Onda 4 — faixa-10 ∥ faixa-11 ∥ faixa-12

#### faixa-10 — branch `spec/gofence-cli-faixa-10` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-10`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-012 | Analisador TLS | `claude-sonnet-5` | medium | `internal/surface/tls.go`, `cmd/tls.go` |

#### faixa-11 — branch `spec/gofence-cli-faixa-11` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-11`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-013 | Crawler AST | `claude-sonnet-5` | medium | `internal/surface/crawler.go`, `cmd/crawl.go` |

#### faixa-12 — branch `spec/gofence-cli-faixa-12` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-12`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-014 | Templates de vulnerabilidade | `claude-sonnet-5` | medium | `internal/surface/vulns.go`, `cmd/vulns.go` |

### Onda 5 — faixa-13 ∥ faixa-14 ∥ faixa-15

#### faixa-13 — branch `spec/gofence-cli-faixa-13` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-13`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-015 | Gerador de payloads | `claude-sonnet-5` | medium | `internal/exploit/payload.go`, `cmd/payload.go` |

#### faixa-14 — branch `spec/gofence-cli-faixa-14` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-14`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-016 | Multi-handler | `claude-sonnet-5` | medium | `internal/exploit/handler.go`, `cmd/listen.go` |

#### faixa-15 — branch `spec/gofence-cli-faixa-15` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-15`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-017 | Engine de brute force | `claude-sonnet-5` | medium | `internal/exploit/brute.go`, `cmd/brute.go` |

### Onda 6 — faixa-16 ∥ faixa-17

#### faixa-16 — branch `spec/gofence-cli-faixa-16` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-16`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-018 | TUI Bubbletea | `claude-sonnet-5` | medium | `internal/ux/tui.go` |

#### faixa-17 — branch `spec/gofence-cli-faixa-17` — worktree `../onp-worktrees/Projetos-gofence-cli-faixa-17`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-019 | Modo headless/pipeline | `claude-sonnet-5` | medium | `internal/ux/headless.go` |

## Gestão de branches e commits

1. branch de trabalho `spec/gofence-cli` criada do ponto atual (se ainda não existir)
2. cada faixa nasce dela como branch própria e roda no seu worktree — **1 tarefa = 1 commit** (`T-xxx feature: título`)
3. terminou a onda → merge `--no-ff` de cada faixa de volta, na ordem; conflito interrompe a faixa e pede resolução humana
4. faixa mesclada → worktree removido, branch apagada, tarefa marcada `[concluida]` no tasks.md
5. gate final na branch de trabalho: `onp-spec verify gofence-cli` + `onp-spec audit --ci` — **exit 0 ou não está pronto**

## Como executar

### ▶ Paralelo nativo no Antigravity (janelas limpas, sem Claude CLI)

1. **Prepare a branch de trabalho e os worktrees** (terminal, na raiz do repositório):

```bash
git checkout -b spec/gofence-cli   # ou: git checkout spec/gofence-cli
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-1 -b spec/gofence-cli-faixa-1
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-2 -b spec/gofence-cli-faixa-2
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-3 -b spec/gofence-cli-faixa-3
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-4 -b spec/gofence-cli-faixa-4
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-5 -b spec/gofence-cli-faixa-5
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-6 -b spec/gofence-cli-faixa-6
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-7 -b spec/gofence-cli-faixa-7
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-8 -b spec/gofence-cli-faixa-8
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-9 -b spec/gofence-cli-faixa-9
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-10 -b spec/gofence-cli-faixa-10
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-11 -b spec/gofence-cli-faixa-11
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-12 -b spec/gofence-cli-faixa-12
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-13 -b spec/gofence-cli-faixa-13
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-14 -b spec/gofence-cli-faixa-14
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-15 -b spec/gofence-cli-faixa-15
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-16 -b spec/gofence-cli-faixa-16
git worktree add ../onp-worktrees/Projetos-gofence-cli-faixa-17 -b spec/gofence-cli-faixa-17
```

2. **Abra um agente NOVO por faixa** (janela limpa) e cole o prompt da faixa:

#### Prompt — faixa-1

```
Você executa as tarefas da faixa-1 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-1 (branch spec/gofence-cli-faixa-1) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-001 — "Projeto Go, módulos e dependências"
  critérios/refs: US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009, US-010, US-011, US-012, US-013, US-014, US-015
  arquivos permitidos (e seus testes): go.mod, go.sum, main.go
  mensagem de commit: "T-001 gofence-cli: Projeto Go, módulos e dependências"
T-006 — "Root command e detecção TUI/headless"
  critérios/refs: AC-028 (dashboard principal), AC-030 (saída JSON canalizável)
  arquivos permitidos (e seus testes): cmd/root.go, main.go
  mensagem de commit: "T-006 gofence-cli: Root command e detecção TUI/headless"
T-020 — "Integração final e testes"
  critérios/refs: US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009, US-010, US-011, US-012, US-013, US-014, US-015
  arquivos permitidos (e seus testes): main.go, cmd/*.go
  mensagem de commit: "T-020 gofence-cli: Integração final e testes"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-2

```
Você executa as tarefas da faixa-2 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-2 (branch spec/gofence-cli-faixa-2) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-002 — "Configuração (Viper)"
  critérios/refs: US-002, US-015
  arquivos permitidos (e seus testes): internal/config/config.go
  mensagem de commit: "T-002 gofence-cli: Configuração (Viper)"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-3

```
Você executa as tarefas da faixa-3 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-3 (branch spec/gofence-cli-faixa-3) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-003 — "HTTP client customizado"
  critérios/refs: US-004, US-006, US-007, US-010
  arquivos permitidos (e seus testes): pkg/httpclient/client.go
  mensagem de commit: "T-003 gofence-cli: HTTP client customizado"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-4

```
Você executa as tarefas da faixa-4 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-4 (branch spec/gofence-cli-faixa-4) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-004 — "ScopeGuard"
  critérios/refs: AC-026 (bloqueio de IP fora do escopo), AC-027 (liberação de IP dentro do escopo)
  arquivos permitidos (e seus testes): internal/data/scope.go, internal/data/db.go
  mensagem de commit: "T-004 gofence-cli: ScopeGuard"
T-005 — "SQLite schema e models"
  critérios/refs: AC-023 (criação de workspace), AC-024 (persistência de hosts), AC-025 (persistência de findings)
  arquivos permitidos (e seus testes): internal/data/db.go, internal/data/models.go, internal/data/workspace.go
  mensagem de commit: "T-005 gofence-cli: SQLite schema e models"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-5

```
Você executa as tarefas da faixa-5 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-5 (branch spec/gofence-cli-faixa-5) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-007 — "Rate limiter"
  critérios/refs: AC-032 (perfil Sneaky), AC-033 (perfil Normal), AC-034 (perfil Aggressive)
  arquivos permitidos (e seus testes): internal/ux/ratelimit.go
  mensagem de commit: "T-007 gofence-cli: Rate limiter"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-6

```
Você executa as tarefas da faixa-6 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-6 (branch spec/gofence-cli-faixa-6) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-008 — "DNS brute-force e AXFR"
  critérios/refs: AC-001 (brute-force de subdomínios), AC-002 (transferência de zona), AC-003 (concorrência configurável)
  arquivos permitidos (e seus testes): internal/recon/dns.go, cmd/dns.go
  mensagem de commit: "T-008 gofence-cli: DNS brute-force e AXFR"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-7

```
Você executa as tarefas da faixa-7 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-7 (branch spec/gofence-cli-faixa-7) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-009 — "OSINT clients"
  critérios/refs: AC-004 (consulta Shodan), AC-005 (consulta multi-provider)
  arquivos permitidos (e seus testes): internal/recon/osint.go, cmd/osint.go
  mensagem de commit: "T-009 gofence-cli: OSINT clients"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-8

```
Você executa as tarefas da faixa-8 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-8 (branch spec/gofence-cli-faixa-8) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-010 — "Port scanner TCP/UDP"
  critérios/refs: AC-006 (varredura TCP rápida), AC-007 (varredura UDP)
  arquivos permitidos (e seus testes): internal/recon/portscan.go, cmd/port.go
  mensagem de commit: "T-010 gofence-cli: Port scanner TCP/UDP"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-9

```
Você executa as tarefas da faixa-9 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-9 (branch spec/gofence-cli-faixa-9) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-011 — "Fuzzer web"
  critérios/refs: AC-008 (fuzzing de caminhos), AC-009 (fuzzing de cabeçalhos), AC-010 (stream de wordlist (memória))
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-011 gofence-cli: Fuzzer web"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-10

```
Você executa as tarefas da faixa-10 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-10 (branch spec/gofence-cli-faixa-10) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-012 — "Analisador TLS"
  critérios/refs: AC-011 (inspeção de certificado), AC-012 (detecção de TLS downgrade)
  arquivos permitidos (e seus testes): internal/surface/tls.go, cmd/tls.go
  mensagem de commit: "T-012 gofence-cli: Analisador TLS"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-11

```
Você executa as tarefas da faixa-11 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-11 (branch spec/gofence-cli-faixa-11) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-013 — "Crawler AST"
  critérios/refs: AC-013 (extração de links), AC-014 (detecção de segredos)
  arquivos permitidos (e seus testes): internal/surface/crawler.go, cmd/crawl.go
  mensagem de commit: "T-013 gofence-cli: Crawler AST"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-12

```
Você executa as tarefas da faixa-12 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-12 (branch spec/gofence-cli-faixa-12) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-014 — "Templates de vulnerabilidade"
  critérios/refs: AC-015 (execução de template), AC-016 (execução em lote)
  arquivos permitidos (e seus testes): internal/surface/vulns.go, cmd/vulns.go
  mensagem de commit: "T-014 gofence-cli: Templates de vulnerabilidade"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-13

```
Você executa as tarefas da faixa-13 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-13 (branch spec/gofence-cli-faixa-13) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-015 — "Gerador de payloads"
  critérios/refs: AC-017 (payload reverso Bash), AC-018 (payload Python)
  arquivos permitidos (e seus testes): internal/exploit/payload.go, cmd/payload.go
  mensagem de commit: "T-015 gofence-cli: Gerador de payloads"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-14

```
Você executa as tarefas da faixa-14 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-14 (branch spec/gofence-cli-faixa-14) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-016 — "Multi-handler"
  critérios/refs: AC-019 (escuta e recepção), AC-020 (múltiplas sessões)
  arquivos permitidos (e seus testes): internal/exploit/handler.go, cmd/listen.go
  mensagem de commit: "T-016 gofence-cli: Multi-handler"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-15

```
Você executa as tarefas da faixa-15 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-15 (branch spec/gofence-cli-faixa-15) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-017 — "Engine de brute force"
  critérios/refs: AC-021 (brute force SSH), AC-022 (brute force HTTP Basic)
  arquivos permitidos (e seus testes): internal/exploit/brute.go, cmd/brute.go
  mensagem de commit: "T-017 gofence-cli: Engine de brute force"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-16

```
Você executa as tarefas da faixa-16 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-16 (branch spec/gofence-cli-faixa-16) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-018 — "TUI Bubbletea"
  critérios/refs: AC-028 (dashboard principal), AC-029 (atualização em tempo real)
  arquivos permitidos (e seus testes): internal/ux/tui.go
  mensagem de commit: "T-018 gofence-cli: TUI Bubbletea"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-17

```
Você executa as tarefas da faixa-17 da feature "gofence-cli" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/Projetos-gofence-cli-faixa-17 (branch spec/gofence-cli-faixa-17) — já preparado.
Leia primeiro: .spec/features/gofence-cli/spec.md, .spec/features/gofence-cli/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-019 — "Modo headless/pipeline"
  critérios/refs: AC-030 (saída JSON canalizável), AC-031 (encadeamento de comandos)
  arquivos permitidos (e seus testes): internal/ux/headless.go
  mensagem de commit: "T-019 gofence-cli: Modo headless/pipeline"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `node --test` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

3. **Todas terminaram? Mescle na ordem e marque as tarefas** (na árvore principal):

```bash
git merge --no-ff spec/gofence-cli-faixa-1 -m "merge faixa-1 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-1 && git branch -d spec/gofence-cli-faixa-1
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-001 concluida
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-006 concluida
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-020 concluida
git merge --no-ff spec/gofence-cli-faixa-2 -m "merge faixa-2 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-2 && git branch -d spec/gofence-cli-faixa-2
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-002 concluida
git merge --no-ff spec/gofence-cli-faixa-3 -m "merge faixa-3 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-3 && git branch -d spec/gofence-cli-faixa-3
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-003 concluida
git merge --no-ff spec/gofence-cli-faixa-4 -m "merge faixa-4 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-4 && git branch -d spec/gofence-cli-faixa-4
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-004 concluida
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-005 concluida
git merge --no-ff spec/gofence-cli-faixa-5 -m "merge faixa-5 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-5 && git branch -d spec/gofence-cli-faixa-5
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-007 concluida
git merge --no-ff spec/gofence-cli-faixa-6 -m "merge faixa-6 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-6 && git branch -d spec/gofence-cli-faixa-6
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-008 concluida
git merge --no-ff spec/gofence-cli-faixa-7 -m "merge faixa-7 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-7 && git branch -d spec/gofence-cli-faixa-7
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-009 concluida
git merge --no-ff spec/gofence-cli-faixa-8 -m "merge faixa-8 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-8 && git branch -d spec/gofence-cli-faixa-8
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-010 concluida
git merge --no-ff spec/gofence-cli-faixa-9 -m "merge faixa-9 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-9 && git branch -d spec/gofence-cli-faixa-9
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-011 concluida
git merge --no-ff spec/gofence-cli-faixa-10 -m "merge faixa-10 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-10 && git branch -d spec/gofence-cli-faixa-10
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-012 concluida
git merge --no-ff spec/gofence-cli-faixa-11 -m "merge faixa-11 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-11 && git branch -d spec/gofence-cli-faixa-11
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-013 concluida
git merge --no-ff spec/gofence-cli-faixa-12 -m "merge faixa-12 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-12 && git branch -d spec/gofence-cli-faixa-12
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-014 concluida
git merge --no-ff spec/gofence-cli-faixa-13 -m "merge faixa-13 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-13 && git branch -d spec/gofence-cli-faixa-13
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-015 concluida
git merge --no-ff spec/gofence-cli-faixa-14 -m "merge faixa-14 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-14 && git branch -d spec/gofence-cli-faixa-14
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-016 concluida
git merge --no-ff spec/gofence-cli-faixa-15 -m "merge faixa-15 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-15 && git branch -d spec/gofence-cli-faixa-15
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-017 concluida
git merge --no-ff spec/gofence-cli-faixa-16 -m "merge faixa-16 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-16 && git branch -d spec/gofence-cli-faixa-16
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-018 concluida
git merge --no-ff spec/gofence-cli-faixa-17 -m "merge faixa-17 (gofence-cli)"
git worktree remove ../onp-worktrees/Projetos-gofence-cli-faixa-17 && git branch -d spec/gofence-cli-faixa-17
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa gofence-cli T-019 concluida
```

5. **Gate final** (exit 0 ou não está pronto):

```bash
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs verify gofence-cli
node /home/nixteg/.agents/skills/onp-spec-driven/scripts/onp-spec.mjs audit --ci
```

