# Tasks: Pipeline stdin

> feature: pipeline-stdin

## T-024 — Resolução de alvo (args ou stdin) com testes [concluida]
- Refs: US-017, AC-040, AC-041, AC-042
- Arquivos: internal/ux/headless.go
- Notas: PipeLines(r io.Reader) extraído de PipeInput; StdinPiped(); ResolveTarget(args, r, piped) retorna (alvo, ignoradas, erro). Testes herméticos com strings.Reader em headless_test.go

## T-025 — Fiação nos comandos com alvo [concluida]
- Refs: US-017, AC-040, AC-041, AC-042
- Arquivos: cmd/dns.go, cmd/osint.go, cmd/port.go, cmd/fuzz.go, cmd/tls.go, cmd/crawl.go, cmd/vulns.go, cmd/brute.go
- Notas: Args ExactArgs(1)->MaximumArgs(1); alvo via ResolveTarget com os.Stdin; aviso no STDERR quando há linhas ignoradas. Checagem de escopo continua antes da rede
