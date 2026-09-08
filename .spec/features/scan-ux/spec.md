# Spec: Scan UX

> feature: scan-ux
> status: rascunho

## Contexto

Em modo headless (pipeline UNIX), os comandos longos (`fuzz`, `port`, `dns`)
não dão feedback de progresso — com wordlist de 200k ou varredura de CIDR, o
operador não sabe se o processo está vivo ou quanto falta. Além disso, erros
de conexão transientes derrubam palavras/portas que deveriam ser retentadas.
Esta feature adiciona progresso/ETA no STDERR e retry em erros de conexão.

## Histórias

### US-021 — Progresso e ETA em headless

Como pentester rodando scans longos em pipeline, quero ver progresso e tempo
estimado restante no STDERR, para saber que o processo está vivo e quanto
falta, sem poluir o STDOUT (dados puros).

#### AC-048 — Progresso e ETA aparecem no STDERR em scans longos

- **Dado** um fuzz (ou port scan) com N palavras/portas suficientes para demorar
- **Quando** o comando roda em headless
- **Então** o STDERR recebe atualizações periódicas com itens concluídos/total
  e tempo estimado restante, e o STDOUT continua limpo (só dados)

#### AC-070 — Progresso não quebra o pipeline UNIX

- **Dado** um pipeline (ex.: `gofence dns ... | gofence port ...`)
- **Quando** o comando de cima emite progresso
- **Então** o progresso vai inteiro para o STDERR e o STDOUT continua apenas
  com a saída estruturada (parseável por `jq`/próximo comando)

### US-038 — Retry em erros de conexão

Como pentester, quero que erros de conexão transientes (timeout, reset, DNS
falho) sejam retentados algumas vezes antes de descartar a palavra/porta,
para reduzir falsos negativos em redes instáveis.

#### AC-071 — Erro de conexão é retentado antes de descartar

- **Dado** um alvo que falha a conexão nas primeiras tentativas e responde na terceira
- **Quando** o fuzzer (ou port scan) roda com retries configurados
- **Então** a palavra/porta é eventualmente testada com sucesso e aparece na
  saída, sem descarte na primeira falha

## Fora de escopo

- Barra de progresso interativa estilo TUI em headless — apenas linhas
  periódicas no STDERR (cada linha substitui a anterior se TTY, senão linha nova).
- Retry em respostas HTTP 4xx/5xx — retry é só para erros de transporte
  (conexão/tempo/reset), não para respostas do servidor.
- Persistência do estado de progresso entre execuções (isso é o resume do
  fuzz-parity).

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-022 | Frequência de atualização do progresso: no máximo 1 linha/segundo e a cada ~1% de avanço, para não inundar o STDERR | aberta | A confirmar na execução |
| ASM-023 | Retry padrão: 2 tentativas extras com backoff curto (ex.: 200ms) quando ativo; flag `--retries N` controla | aberta | A confirmar na execução |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-016 | Mostrar progresso por padrão em headless ou só com `--progress`? (por padrão muda a saída de quem já parseia STDERR) | aberta | — |