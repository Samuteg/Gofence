# Plano de execução — fuzz-parity

> gerado por `onp-spec plano` em 2026-09-08 01:13 — NÃO edite à mão;
> mudou tasks.md ou a config? Regenere: `onp-spec plano fuzz-parity`

## Resumo — o que vai acontecer

- **9 tarefa(s) pendente(s)**: 9 em 1 faixa(s) paralela(s) + 0 sequencial(is)
- **1 faixa = 1 worktree + 1 branch + 1 janela de contexto limpa** — faixas não compartilham nenhum arquivo entre si
- tudo acontece na branch de trabalho `spec/fuzz-parity`; mesclagens voltam para ela; levar para a main é decisão sua

## Faixas e ondas

### Onda 1 — faixa-1

#### faixa-1 — branch `spec/fuzz-parity-faixa-1` — worktree `../onp-worktrees/gofence-fuzz-parity-faixa-1`

| tarefa | título | modelo | esforço | arquivos |
|---|---|---|---|---|
| T-038 | Detecção de wildcard/catch-all no fuzzer | `claude-sonnet-5` | medium | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-039 | Filtro por tamanho de resposta | `claude-sonnet-5` | low | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-040 | Whitelist de status | `claude-sonnet-5` | low | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-041 | Recursão em diretórios | `claude-sonnet-5` | high | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-042 | Extensões automáticas -x | `claude-sonnet-5` | low | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-043 | Modo vhost | `claude-sonnet-5` | high | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-044 | robots.txt/sitemap como semente | `claude-sonnet-5` | medium | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-045 | Resume de sessão | `claude-sonnet-5` | high | `internal/surface/fuzzer.go`, `cmd/fuzz.go` |
| T-046 | Auth, cookie e User-Agent via CLI | `claude-sonnet-5` | medium | `cmd/fuzz.go`, `pkg/httpclient/client.go` |

## Gestão de branches e commits

1. branch de trabalho `spec/fuzz-parity` criada do ponto atual (se ainda não existir)
2. cada faixa nasce dela como branch própria e roda no seu worktree — **1 tarefa = 1 commit** (`T-xxx feature: título`)
3. terminou a onda → merge `--no-ff` de cada faixa de volta, na ordem; conflito interrompe a faixa e pede resolução humana
4. faixa mesclada → worktree removido, branch apagada, tarefa marcada `[concluida]` no tasks.md
5. gate final na branch de trabalho: `onp-spec verify fuzz-parity` + `onp-spec audit --ci` — **exit 0 ou não está pronto**

## Como executar

### ▶ Paralelo nativo no Antigravity (janelas limpas, sem Claude CLI)

1. **Prepare a branch de trabalho e os worktrees** (terminal, na raiz do repositório):

```bash
git checkout -b spec/fuzz-parity   # ou: git checkout spec/fuzz-parity
git worktree add ../onp-worktrees/gofence-fuzz-parity-faixa-1 -b spec/fuzz-parity-faixa-1
```

2. **Abra um agente NOVO por faixa** (janela limpa) e cole o prompt da faixa:

#### Prompt — faixa-1

```
Você executa as tarefas da faixa-1 da feature "fuzz-parity" (fluxo onp-spec, spec-anchored).
Trabalhe SOMENTE dentro do worktree ../onp-worktrees/gofence-fuzz-parity-faixa-1 (branch spec/fuzz-parity-faixa-1) — já preparado.
Leia primeiro: .spec/features/fuzz-parity/spec.md, .spec/features/fuzz-parity/tasks.md e .spec/constituicao.md.

Execute NESTA ORDEM (1 tarefa = 1 commit):
T-038 — "Detecção de wildcard/catch-all no fuzzer"
  critérios/refs: AC-047 (Respostas curinga são detectadas e descartadas)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-038 fuzz-parity: Detecção de wildcard/catch-all no fuzzer"
T-039 — "Filtro por tamanho de resposta"
  critérios/refs: AC-062 (Filtro por tamanho de resposta)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-039 fuzz-parity: Filtro por tamanho de resposta"
T-040 — "Whitelist de status"
  critérios/refs: AC-063 (Apenas os status da whitelist aparecem)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-040 fuzz-parity: Whitelist de status"
T-041 — "Recursão em diretórios"
  critérios/refs: AC-064 (Diretório descoberto é re-fuzado recursivamente)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-041 fuzz-parity: Recursão em diretórios"
T-042 — "Extensões automáticas -x"
  critérios/refs: AC-065 (Cada palavra é testada com cada extensão)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-042 fuzz-parity: Extensões automáticas -x"
T-043 — "Modo vhost"
  critérios/refs: AC-066 (Vhosts distintos aparecem, respostas iguais à base são filtradas)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-043 fuzz-parity: Modo vhost"
T-044 — "robots.txt/sitemap como semente"
  critérios/refs: AC-067 (Paths de robots/sitemap entram no fuzz)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-044 fuzz-parity: robots.txt/sitemap como semente"
T-045 — "Resume de sessão"
  critérios/refs: AC-068 (Sessão interrompida é retomada do ponto salvo)
  arquivos permitidos (e seus testes): internal/surface/fuzzer.go, cmd/fuzz.go
  mensagem de commit: "T-045 fuzz-parity: Resume de sessão"
T-046 — "Auth, cookie e User-Agent via CLI"
  critérios/refs: AC-069 (Credenciais, cookie e UA são enviados na requisição)
  arquivos permitidos (e seus testes): cmd/fuzz.go, pkg/httpclient/client.go
  mensagem de commit: "T-046 fuzz-parity: Auth, cookie e User-Agent via CLI"

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
git merge --no-ff spec/fuzz-parity-faixa-1 -m "merge faixa-1 (fuzz-parity)"
git worktree remove ../onp-worktrees/gofence-fuzz-parity-faixa-1 && git branch -d spec/fuzz-parity-faixa-1
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-038 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-039 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-040 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-041 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-042 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-043 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-044 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-045 concluida
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs tarefa fuzz-parity T-046 concluida
```

5. **Gate final** (exit 0 ou não está pronto):

```bash
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs verify fuzz-parity
node /home/MxTeg/.claude/skills/onp-spec-driven/scripts/onp-spec.mjs audit --ci
```

