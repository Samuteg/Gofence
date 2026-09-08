# Tasks: Scan UX

> feature: scan-ux

## T-047 — Progresso e ETA no STDERR em headless [concluida]
- Refs: US-021, AC-048, AC-070
- Arquivos: internal/ux/progress.go, cmd/fuzz.go, cmd/port.go, cmd/dns.go
- Esforço: alto
- Notas: helper de progresso (concluído/total, % e ETA por média de vazão); linha periódica no STDERR (≤1/s e a cada ~1%); STDOUT intocado; desligável por flag --no-progress (Q-016: padrão ligado ou flag? registrar decisão)

## T-048 — Retry em erros de conexão [concluida]
- Refs: US-038, AC-071
- Arquivos: internal/surface/fuzzer.go, internal/recon/portscan.go, cmd/fuzz.go, cmd/port.go
- Esforço: medio
- Notas: flag --retries N (default 2) com backoff curto (200ms); só erros de transporte (timeout/reset/DNS) retentam; respostas 4xx/5xx não; port scan reaproveita T-033