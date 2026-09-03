# Spec: Scope enforcement

> feature: scope-enforcement
> status: auditada

## Contexto

O ScopeGuard existe (`internal/data/scope.go`) mas nenhum comando de rede o
consulta — o bloqueio de alvos fora do escopo contratado hoje só acontece nos
testes. Esta feature liga a guarda de verdade em todos os comandos com alvo
de rede, no modo fail-closed (decisão do dono do produto).

## Histórias

### US-016 — Bloqueio real de alvos fora do escopo

Como pentester com escopo contratado, quero que a CLI recuse de verdade
qualquer alvo fora do escopo, para nunca testar o que não foi contratado.

#### AC-035 — Alvo fora do escopo é bloqueado sem pacote na rede

- **Dado** um workspace ativo com CIDR permitido 10.0.0.0/8
- **Quando** um comando mira 192.168.1.1 (ou nome que resolve para ele)
- **Então** nada é enviado ao alvo e o STDERR registra `Out-of-Scope Blocked`

#### AC-036 — Alvo dentro do escopo passa normalmente

- **Dado** um workspace ativo com CIDR permitido 10.0.0.0/8
- **Quando** um comando mira 10.0.1.5
- **Então** a operação executa normalmente, sem log de bloqueio

#### AC-037 — Sem workspace ativo o comando recusa com orientação

- **Dado** que não há workspace ativo (nem flag `--workspace`)
- **Quando** qualquer comando de rede executa
- **Então** ele sai com erro orientando a criar o workspace e o escopo, sem tocar na rede

#### AC-038 — Workspace com escopo vazio bloqueia tudo

- **Dado** um workspace ativo sem nenhum CIDR cadastrado
- **Quando** qualquer comando de rede executa
- **Então** o alvo é tratado como fora do escopo (bloqueio + log no STDERR)

#### AC-039 — Descoberta em massa filtra resultado por resultado

- **Dado** um workspace ativo com escopo restrito
- **Quando** o brute-force de DNS resolve subdomínios dentro e fora do escopo
- **Então** só os subdomínios dentro do escopo são exibidos e persistidos (os demais geram log de bloqueio)

## Fora de escopo

- Comandos sem alvo de rede (`payload`, `listen`, `report`, `workspace`).
- Bloqueio no nível do resolver DNS de terceiros (a consulta de resolução
  vai ao resolver, não ao alvo — só o uso do IP resolvido é filtrado).

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-009 | Nome que não resolve é tratado como fora do escopo (fail-closed: sem IP não há como provar que está no contratado) | confirmada | Decorre da decisão fail-closed do dono do produto |
| ASM-010 | `osint` entra no bloqueio como os demais, mesmo sem conexão direta ao alvo (postura conservadora e uniforme) | confirmada | Decisão de desenho: todo comando com alvo passa pela guarda |
| ASM-011 | Alvo em notação CIDR (ex.: `port 10.0.0.0/24`) é avaliado pelo endereço-base da faixa, pois o scanner ainda não expande faixas | confirmada | Expansão de CIDR no port é trabalho futuro, fora desta feature |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-009 | Sem workspace ativo ou escopo vazio: bloquear ou permitir? | respondida | Bloquear (fail-closed) — decisão do dono do produto |
