# Tasks: Fuzz advanced

> feature: fuzz-advanced

## T-051 — Auth Bearer no fuzzer [concluida]
- Refs: US-040, AC-074
- Arquivos: internal/surface/fuzzer.go, internal/surface/fuzzer_features.go, cmd/fuzz.go
- Esforço: baixo
- Notas: flag --bearer; seta Authorization: Bearer <token> nas requisições (via SetAuth/FuzzAuth)

## T-052 — Auth NTLM no fuzzer [concluida]
- Refs: US-040, AC-075
- Arquivos: internal/surface/fuzzer.go, internal/surface/fuzzer_features.go, internal/surface/ntlm.go, cmd/fuzz.go
- Esforço: xalto
- Notas: handshake NTLMv2 HTTP (type1 → 401 → type2 → type3); flag --ntlm user:pass; teste hermético com servidor HTTP fake que responde challenge

## T-053 — Fuzzing de parâmetros com payloads [concluida]
- Refs: US-041, AC-076
- Arquivos: internal/surface/fuzzer.go, internal/surface/fuzzer_features.go, cmd/fuzz.go
- Esforço: medio
- Notas: flag --param <nome>; URL vira <base>?<param>=FUZZ (ou preserva outros params); cada palavra vira valor do parâmetro

## T-054 — Modo s3 (buckets) [concluida]
- Refs: US-042, AC-077
- Arquivos: internal/surface/fuzzer_s3.go, cmd/fuzz.go
- Esforço: medio
- Notas: flag --s3 com wordlist de nomes; testa https://<bucket>.s3.amazonaws.com; reporta existência por status (200/301/403 = existe; 404 = não); teste hermético com httptest

## T-055 — Modo dns no fuzzer [concluida]
- Refs: US-043, AC-078
- Arquivos: internal/surface/fuzzer_dns.go, cmd/fuzz.go
- Esforço: medio
- Notas: flag --dns <dominio> reusa recon.Resolver (com --nameserver do root/fuzz); subdomínios que resolvem aparecem com IP