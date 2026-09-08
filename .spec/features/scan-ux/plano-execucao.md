# Plano de execução — scan-ux

> gerado por `onp-spec plano` em 2026-09-08 01:13 — NÃO edite à mão;
> mudou tasks.md ou a config? Regenere: `onp-spec plano scan-ux`

## Resumo — o que vai acontecer

- **2 tarefa(s) pendente(s)**: 2 em 1 faixa(s) paralela(s) + 0 sequencial(is)
- **1 faixa = 1 worktree + 1 branch + 1 janela de contexto limpa** — faixas não compartilham nenhum arquivo entre si
- tudo acontece na branch de trabalho `spec/scan-ux`; mesclagens voltam para ela; levar para a main é decisão sua

## Faixas e ondas

### Onda 1 — faixa-1

#### faixa-1 — branch `spec/scan-ux-faixa-1` — worktree `../onp-worktrees/gofence-scan-ux-faixa-1`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-047 | Progresso e ETA no STDERR em headless | `claude-sonnet-5` | high | `internal/ux/progress.go`, `cmd/fuzz.go`, `cmd/port.go`, `cmd/dns.go` |
| T-048 | Retry em erros de conexão | `claude-sonnet-5` | medium | `internal/surface/fuzzer.go`, `internal/recon/portscan.go`, `cmd/fuzz.go`, `cmd/port.go` |

## Gestão de branches e commits

1. branch de trabalho `spec/scan-ux` criada do ponto atual (se ainda não existir)
2. cada faixa nasce dela como branch própria e roda no seu worktree — **1 tarefa = 1 commit** (`T-xxx feature: título`)
3. terminou a onda → merge `--no-ff` de cada faixa de volta, na ordem; conflito interrompe a faixa e pede resolução humana
4. faixa mesclada → worktree removido, branch apagada, tarefa marcada `[concluida]` no tasks.md
5. gate final na branch de trabalho: `onp-spec verify scan-ux` + `onp-spec audit --ci` — **exit 0 ou não está pronto**

## Como executar

### ▶ Paralelo nativo no Antigravity (janelas limpas, sem Claude CLI)

1. **Prepare a branch de trabalho e os worktrees** (terminal, na raiz do repositório):

```bash
git checkout -b spec/scan-ux   # ou: git checkout spec/scan-ux
git worktree add ../onp-worktrees/gofence-scan-ux-faixa-1 -b spec/scan-ux-faixa-1
```

2. **Abra um agente NOVO por faixa** (janela limpa) e cole o prompt da faixa:

#### Prompt — faixa-1

```
Você executa as tarefas da faixa-1 da feature "scan-ux" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/gofence-scan-ux-faixa-1 (branch spec/scan-ux-faixa-1) — já preparado.
Leia primeiro: .spec/features/scan-ux/spec.md, .spec/features/scan-ux/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-047 — "Progresso e ETA no STDERR em headless"
  critérios/refs: AC-048 (Progresso e ETA aparecem no STDERR em scans longos), AC-070 (Progresso não quebra o pipeline UNIX)
  arquivos permitidos (e seus testes): internal/ux/progress.go, cmd/fuzz.go, cmd/port.go, cmd/dns.go
  mensagem de commit: "T-047 scan-ux: Progresso e ETA no STDERR em headless"
T-048 — "Retry em erros de conexão"
  critérios/refs: AC-071 (Erro de conexão é retentado antes de descartar)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, internal/recon/portscan.go, cmd/fuzz.go, cmd/port.go
  mensagem de commit: "T-048 scan-ux: Retry em erros de conexão"

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
git merge --no-ff spec/scan-ux-faixa-1 -m "merge faixa-1 (scan-ux)"
git worktree remove ../onp-worktrees/gofence-scan-ux-faixa-1 && git branch -d spec/scan-ux-faixa-1
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa scan-ux T-047 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa scan-ux T-048 concluida
```

5. **Gate final** (exit 0 ou não está pronto):

```bash
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs verify scan-ux
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs audit --ci
```

