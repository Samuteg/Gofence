# Spec: Pipeline stdin

> feature: pipeline-stdin
> status: auditada

## Contexto

`PipeInput()` existe mas nenhum comando lê stdin — `gofence dns alvo.com |
gofence port` não funciona. Esta feature faz os comandos com alvo aceitarem
o alvo via pipe, mantendo o argumento explícito como prioridade.

## Histórias

### US-017 — Alvo via pipe entre comandos

Como pentester, quero encadear comandos via pipe UNIX sem repetir o alvo,
para montar pipelines de reconhecimento.

#### AC-040 — Sem argumento, o alvo vem da primeira linha do stdin

- **Dado** stdin canalizado com `10.0.0.1` na primeira linha (e outras depois)
- **Quando** um comando de rede roda sem argumento posicional
- **Então** ele usa `10.0.0.1` como alvo e avisa no STDERR que ignorou as demais linhas

#### AC-041 — Sem argumento e sem pipe, o comando reclama o uso

- **Dado** stdin ligado ao terminal (sem pipe) e nenhum argumento
- **Quando** um comando de rede roda
- **Então** ele sai com erro pedindo o alvo, sem tocar na rede

#### AC-042 — Argumento explícito tem prioridade sobre o pipe

- **Dado** stdin canalizado com conteúdo e argumento `10.9.9.9` na linha de comando
- **Quando** o comando roda
- **Então** o alvo é `10.9.9.9` e o stdin é ignorado

## Fora de escopo

- Parse de JSON no stdin (só texto; vale o primeiro campo da linha).
- Múltiplos alvos por pipe (só o primeiro é usado).
- `listen` (porta opcional já existe) e comandos sem alvo.

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-012 | Vale o primeiro campo separado por espaço da linha (ex.: saída `sub IP` do dns vira o subdomínio, que o dial resolve) | confirmada | Convenção documentada; comandos que discam resolvem hostnames |
| ASM-013 | A checagem de escopo (fail-closed) continua valendo para alvos vindos do pipe, sem exceção | confirmada | Decorre da feature scope-enforcement já auditada |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-010 | Um pipe deveria alimentar vários alvos em sequência (um scan por linha)? | respondida | Não nesta feature — só o primeiro alvo, com aviso; múltiplos alvos é trabalho futuro |
