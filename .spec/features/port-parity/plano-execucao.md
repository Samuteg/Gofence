# Plano de execução — port-parity

> gerado por `onp-spec plano` em 2026-09-08 01:13 — NÃO edite à mão;
> mudou tasks.md ou a config? Regenere: `onp-spec plano port-parity`

## Resumo — o que vai acontecer

- **10 tarefa(s) pendente(s)**: 10 em 3 faixa(s) paralela(s) + 0 sequencial(is)
- **1 faixa = 1 worktree + 1 branch + 1 janela de contexto limpa** — faixas não compartilham nenhum arquivo entre si
- tudo acontece na branch de trabalho `spec/port-parity`; mesclagens voltam para ela; levar para a main é decisão sua

## Faixas e ondas

### Onda 1 — faixa-1 ∥ faixa-2 ∥ faixa-3

#### faixa-1 — branch `spec/port-parity-faixa-1` — worktree `../onp-worktrees/gofence-port-parity-faixa-1`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-028 | Expandir CIDR no port scan | `claude-sonnet-5` | medium | `internal/recon/portscan.go`, `cmd/port.go` |
| T-029 | Banner grabbing e detecção de versão | `claude-sonnet-5` | high | `internal/recon/portscan.go` |
| T-031 | Ping sweep / descoberta de host | `claude-sonnet-5` | medium | `internal/recon/hostdiscovery.go`, `cmd/port.go` |
| T-033 | Timing e retries configuráveis | `claude-sonnet-5` | medium | `internal/recon/portscan.go`, `cmd/port.go` |
| T-034 | Suporte a IPv6 | `claude-sonnet-5` | low | `internal/recon/portscan.go` |
| T-035 | Lista de alvos -iL | `claude-sonnet-5` | medium | `cmd/port.go`, `cmd/helpers.go` |
| T-036 | Framework de scripts Go (NSE-lite) | `claude-sonnet-5` | xhigh | `internal/recon/scripts.go`, `internal/recon/scripts_ssh.go`, `internal/recon/scripts_dns.go`, `internal/recon/scripts_smtp.go`, `cmd/port.go` |
| T-037 | Saída XML compatível com nmap -oX | `claude-sonnet-5` | medium | `internal/recon/xml.go`, `cmd/port.go` |

#### faixa-2 — branch `spec/port-parity-faixa-2` — worktree `../onp-worktrees/gofence-port-parity-faixa-2`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-030 | SYN scan com raw socket | `claude-sonnet-5` | xhigh | `internal/recon/synscan.go`, `go.mod` |

#### faixa-3 — branch `spec/port-parity-faixa-3` — worktree `../onp-worktrees/gofence-port-parity-faixa-3`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-032 | Fingerprint de SO embutido | `claude-sonnet-5` | high | `internal/recon/osfingerprint.go`, `internal/assets/os-fingerprints.yaml`, `internal/assets/assets.go` |

## Gestão de branches e commits

1. branch de trabalho `spec/port-parity` criada do ponto atual (se ainda não existir)
2. cada faixa nasce dela como branch própria e roda no seu worktree — **1 tarefa = 1 commit** (`T-xxx feature: título`)
3. terminou a onda → merge `--no-ff` de cada faixa de volta, na ordem; conflito interrompe a faixa e pede resolução humana
4. faixa mesclada → worktree removido, branch apagada, tarefa marcada `[concluida]` no tasks.md
5. gate final na branch de trabalho: `onp-spec verify port-parity` + `onp-spec audit --ci` — **exit 0 ou não está pronto**

## Como executar

### ▶ Paralelo nativo no Antigravity (janelas limpas, sem Claude CLI)

1. **Prepare a branch de trabalho e os worktrees** (terminal, na raiz do repositório):

```bash
git checkout -b spec/port-parity   # ou: git checkout spec/port-parity
git worktree add ../onp-worktrees/gofence-port-parity-faixa-1 -b spec/port-parity-faixa-1
git worktree add ../onp-worktrees/gofence-port-parity-faixa-2 -b spec/port-parity-faixa-2
git worktree add ../onp-worktrees/gofence-port-parity-faixa-3 -b spec/port-parity-faixa-3
```

2. **Abra um agente NOVO por faixa** (janela limpa) e cole o prompt da faixa:

#### Prompt — faixa-1

```
Você executa as tarefas da faixa-1 da feature "port-parity" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/gofence-port-parity-faixa-1 (branch spec/port-parity-faixa-1) — já preparado.
Leia primeiro: .spec/features/port-parity/spec.md, .spec/features/port-parity/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-028 — "Expandir CIDR no port scan"
  critérios/refs: AC-046 (Alvo em CIDR é expandido e cada host é varrido), AC-049 (Resultado por host individual)
  arquivos permitidos (e seus testes): internal/recon/portscan.go, cmd/port.go
  mensagem de commit: "T-028 port-parity: Expandir CIDR no port scan"
T-029 — "Banner grabbing e detecção de versão"
  critérios/refs: AC-050 (Banner identificado vira serviço+versão no resultado), AC-051 (Serviço sem banner cai no mapa estático como fallback)
  arquivos permitidos (e seus testes): internal/recon/portscan.go
  mensagem de commit: "T-029 port-parity: Banner grabbing e detecção de versão"
T-031 — "Ping sweep / descoberta de host"
  critérios/refs: AC-054 (Hosts vivos da faixa são listados)
  arquivos permitidos (e seus testes): internal/recon/hostdiscovery.go, cmd/port.go
  mensagem de commit: "T-031 port-parity: Ping sweep / descoberta de host"
T-033 — "Timing e retries configuráveis"
  critérios/refs: AC-056 (Retry em timeout antes de marcar fechada)
  arquivos permitidos (e seus testes): internal/recon/portscan.go, cmd/port.go
  mensagem de commit: "T-033 port-parity: Timing e retries configuráveis"
T-034 — "Suporte a IPv6"
  critérios/refs: AC-057 (Alvo IPv6 literal é varrido sem erro)
  arquivos permitidos (e seus testes): internal/recon/portscan.go
  mensagem de commit: "T-034 port-parity: Suporte a IPv6"
T-035 — "Lista de alvos -iL"
  critérios/refs: AC-058 (Alvos de arquivo são varridos um a um)
  arquivos permitidos (e seus testes): cmd/port.go, cmd/helpers.go
  mensagem de commit: "T-035 port-parity: Lista de alvos -iL"
T-036 — "Framework de scripts Go (NSE-lite)"
  critérios/refs: AC-059 (Script registrado roda para o serviço detectado), AC-060 (Checagem por protocolo executa e reporta)
  arquivos permitidos (e seus testes): internal/recon/scripts.go, internal/recon/scripts_ssh.go, internal/recon/scripts_dns.go, internal/recon/scripts_smtp.go, cmd/port.go
  mensagem de commit: "T-036 port-parity: Framework de scripts Go (NSE-lite)"
T-037 — "Saída XML compatível com nmap -oX"
  critérios/refs: AC-061 (-oX gera XML compatível com nmap)
  arquivos permitidos (e seus testes): internal/recon/xml.go, cmd/port.go
  mensagem de commit: "T-037 port-parity: Saída XML compatível com nmap -oX"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `go test -json ./... | python3 .spec/go-tap.py` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-2

```
Você executa as tarefas da faixa-2 da feature "port-parity" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/gofence-port-parity-faixa-2 (branch spec/port-parity-faixa-2) — já preparado.
Leia primeiro: .spec/features/port-parity/spec.md, .spec/features/port-parity/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-030 — "SYN scan com raw socket"
  critérios/refs: AC-052 (SYN scan reporta porta aberta), AC-053 (Sem privilégio, erro claro pedindo root)
  arquivos permitidos (e seus testes): internal/recon/synscan.go, go.mod
  mensagem de commit: "T-030 port-parity: SYN scan com raw socket"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `go test -json ./... | python3 .spec/go-tap.py` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

#### Prompt — faixa-3

```
Você executa as tarefas da faixa-3 da feature "port-parity" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/gofence-port-parity-faixa-3 (branch spec/port-parity-faixa-3) — já preparado.
Leia primeiro: .spec/features/port-parity/spec.md, .spec/features/port-parity/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-032 — "Fingerprint de SO embutido"
  critérios/refs: AC-055 (Fingerprint TCP produz palpite de SO)
  arquivos permitidos (e seus testes): internal/recon/osfingerprint.go, internal/assets/os-fingerprints.yaml, internal/assets/assets.go
  mensagem de commit: "T-032 port-parity: Fingerprint de SO embutido"

Regras inegociáveis:
- Todo critério de aceite referenciado vira teste com @spec:AC-xxx no título.
- NUNCA enfraqueça, pule (skip/todo) ou apague um teste para passar — teste pulado não é prova e o audit acusa.
- Rode os testes localmente com `go test -json ./... | python3 .spec/go-tap.py` até passarem.
- NÃO edite tasks.md, NÃO rode onp-spec verify/audit e NÃO toque em outras tarefas — o orquestrador cuida disso.
- Ao final de CADA tarefa: `git add` só no que você tocou e um commit próprio.
Quando a última tarefa estiver commitada, PARE e informe o resultado — a mesclagem é do orquestrador.
```

3. **Todas terminaram? Mescle na ordem e marque as tarefas** (na árvore principal):

```bash
git merge --no-ff spec/port-parity-faixa-1 -m "merge faixa-1 (port-parity)"
git worktree remove ../onp-worktrees/gofence-port-parity-faixa-1 && git branch -d spec/port-parity-faixa-1
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-028 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-029 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-031 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-033 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-034 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-035 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-036 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-037 concluida
git merge --no-ff spec/port-parity-faixa-2 -m "merge faixa-2 (port-parity)"
git worktree remove ../onp-worktrees/gofence-port-parity-faixa-2 && git branch -d spec/port-parity-faixa-2
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-030 concluida
git merge --no-ff spec/port-parity-faixa-3 -m "merge faixa-3 (port-parity)"
git worktree remove ../onp-worktrees/gofence-port-parity-faixa-3 && git branch -d spec/port-parity-faixa-3
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa port-parity T-032 concluida
```

5. **Gate final** (exit 0 ou não está pronto):

```bash
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs verify port-parity
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs audit --ci
```

