# Tasks: Workspace delete

> feature: workspace-delete

## T-026 — Deleção lógica no banco com testes [concluida]
- Refs: US-018, AC-043, AC-044
- Arquivos: internal/data/db.go
- Notas: WorkspaceDelete(id) com UPDATE deleted_at + RowsAffected (0 = erro). Testes em db_test.go: some do list e mantém dados; inexistente retorna erro

## T-027 — Comando workspace delete [concluida]
- Refs: US-018, AC-043, AC-044, AC-045
- Arquivos: cmd/workspace.go
- Notas: `workspace delete <id|nome>` via resolveWorkspaceID; limpa KV active_workspace quando for o deletado. Testado via camada de dados (AC-045 em db_test.go com KV)
