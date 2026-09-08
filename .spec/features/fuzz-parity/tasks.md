# Tasks: Fuzz parity

> feature: fuzz-parity

## T-038 — Detecção de wildcard/catch-all no fuzzer [pendente]
- Refs: US-020, AC-047
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: medio
- Notas: requisição de referência com path aleatório antes da onda; respostas com status+size iguais à referência são descartadas e contadas; aviso no STDERR "wildcard detected"; espelha detectWildcard do DNS

## T-039 — Filtro por tamanho de resposta [pendente]
- Refs: US-020, AC-062
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: baixo
- Notas: flag --exclude-length (int ou lista); respostas com size no filtro são suprimidas mesmo com status ≠ 404

## T-040 — Whitelist de status [pendente]
- Refs: US-031, AC-063
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: baixo
- Notas: flag --status-codes (ex.: 200,301); quando presente, só esses status aparecem (substitui a lógica atual de "exibir tudo exceto 404/ignorados")

## T-041 — Recursão em diretórios [pendente]
- Refs: US-032, AC-064
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: alto
- Notas: flag --recursive com --depth; BFS: diretórios achados (status 200/301 + path terminando em /) viram novos alvos; deduplicação de URLs; limite de profundidade

## T-042 — Extensões automáticas -x [pendente]
- Refs: US-033, AC-065
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: baixo
- Notas: flag -x php,html; cada palavra vira N variantes com extensão; remove a extensão da palavra original se já presente

## T-043 — Modo vhost [pendente]
- Refs: US-034, AC-066
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: alto
- Notas: flag --vhost <url-base>; requisições com Host: FUZZ; resposta de referência sem Host; vhosts com corpo/tamanho/status distintos da base aparecem, iguais são filtrados

## T-044 — robots.txt/sitemap como semente [pendente]
- Refs: US-035, AC-067
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: medio
- Notas: flag --robots e --sitemap; fetch do recurso, extrai Disallow:/Allow: (robots) e <loc> (sitemap), insere no início da fila de fuzz

## T-045 — Resume de sessão [pendente]
- Refs: US-036, AC-068
- Arquivos: internal/surface/fuzzer.go, cmd/fuzz.go
- Esforço: alto
- Notas: flag -o <arquivo-estado> grava progresso (JSON: palavra atual, achados, contadores); --resume <estado> continua de onde parou; estado gravado periodicamente e no fim

## T-046 — Auth, cookie e User-Agent via CLI [pendente]
- Refs: US-037, AC-069
- Arquivos: cmd/fuzz.go, pkg/httpclient/client.go
- Esforço: medio
- Notas: flags --auth user:pass (Basic), --cookie "k=v", --user-agent "…"; aplicadas em toda requisição do fuzzer (e idealmente nos outros comandos HTTP)