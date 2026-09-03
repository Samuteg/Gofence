# LIÇÕES — mantido pelo motor (`onp-spec licoes`)

> Não edite à mão: qualquer escrita do motor sobrescreve este arquivo.
> Estado canônico em `.spec/licoes.json`; mutação só via `onp-spec licoes`.

## Confirmadas — carregue no Especificar/Projetar

Corroboradas em múltiplas features. Aplique como guia.

_nenhuma_

## Candidatas — em observação, NÃO aplicar ainda

Vistas em uma feature só. Registradas, não confiadas.

### L-001 — Escrever o teste anotado @spec junto de cada critério de aceite, antes de implementar — nunca depois do audit acusar
- sinal: `AC_SEM_TESTE` · recorrência: 1 feature(s) · penalidades: 0
- features: scope-enforcement
- última evidência: AC-035 (scope-enforcement, 2026-09-03T01:28:21.965Z)

### L-002 — Conferir cada caminho de Arquivos: contra a árvore real antes de marcar a tarefa como concluída — glob e arquivo movido quebram o audit
- sinal: `ARQUIVO_INEXISTENTE` · recorrência: 1 feature(s) · penalidades: 0
- features: gofence-cli
- última evidência: T-005 (gofence-cli, 2026-09-03T01:28:28.520Z)

## Quarentena — aplicadas e falharam, ignorar

A falha recorreu mesmo com a lição aplicada. Revisão é do usuário.

_nenhuma_
