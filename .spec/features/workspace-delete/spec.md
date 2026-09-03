# Spec: Workspace delete

> feature: workspace-delete
> status: auditada

## Contexto

Workspaces têm coluna `deleted_at` (soft delete, Q-007) mas nenhum comando a
usa — engajamentos encerrados poluem o `list` para sempre. Esta feature
adiciona `workspace delete` com deleção lógica.

## Histórias

### US-018 — Encerrar workspace sem apagar histórico

Como pentester, quero marcar um engajamento como encerrado mantendo o
histórico para auditoria, para que a lista mostre só o trabalho ativo.

#### AC-043 — Delete esconde o workspace do list mantendo os dados

- **Dado** um workspace `Cliente X` com hosts e findings
- **Quando** executo `gofence workspace delete "Cliente X"`
- **Então** ele some do `workspace list` mas as linhas continuam no banco com `deleted_at` preenchido

#### AC-044 — Deletar o inexistente avisa com erro claro

- **Dado** que não existe workspace `Fantasma`
- **Quando** executo `gofence workspace delete Fantasma`
- **Então** o comando sai com erro dizendo que o workspace não foi encontrado (e nada muda no banco)

#### AC-045 — Deletar o workspace ativo limpa a seleção

- **Dado** que `Cliente X` é o workspace ativo
- **Quando** executo `gofence workspace delete "Cliente X"`
- **Então** a marcação de ativo é limpa (comandos seguintes pedem um novo workspace ativo em vez de mirar um morto)

## Fora de escopo

- Deleção física (`--hard`): só lógica, para preservar auditoria.
- Reativar workspace (`undelete`): trabalho futuro.

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-014 | `delete` aceita id ou nome, mesma convenção do `workspace scope` | confirmada | Consistência com comando existente (resolveWorkspaceID) |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-011 | Precisa de deleção física (`--hard`) nesta feature? | respondida | Não — só lógica; auditoria manda preservar |
