# Spec: Fuzz advanced

> feature: fuzz-advanced
> status: rascunho

## Contexto

O fuzzer web (features fuzz-parity) já cobre paths, vhosts, wildcard,
recursão e auth Basic. As decisões da fuzz-parity deixaram explícito como
trabalho futuro: Bearer/NTLM além de Basic (Q-015), fuzzing de parâmetros
com payloads (Fora de escopo) e modo s3/dns no estilo gobuster (Fora de
escopo). Esta feature entrega esses quatro avanços.

## Histórias

### US-040 — Auth Bearer/NTLM no fuzzer

Como pentester, quero enviar tokens Bearer e autenticação NTLM no fuzzer,
para testar APIs com JWT/OAuth e serviços Windows.

#### AC-074 — Token Bearer é enviado no cabeçalho Authorization

- **Dado** um alvo que só responde 200 com `Authorization: Bearer <token>`
- **Quando** o fuzzer roda com `--bearer <token>`
- **Então** as requisições carregam o token e a resposta 200 aparece na saída

#### AC-075 — Auth NTLM é aplicada com handshake challenge/response

- **Dado** um alvo que exige NTLM (responde 401 com WWW-Authenticate: NTLM)
- **Quando** o fuzzer roda com `--ntlm user:pass`
- **Então** o handshake NTLM (type1 → type2 → type3) ocorre e a resposta autenticada (200) aparece

### US-041 — Fuzzing de parâmetros com payloads

Como pentester, quero fuzzar valores de parâmetros (GET/POST) com uma
wordlist de payloads, para testar injeção em campos específicos.

#### AC-076 — Parâmetro é fuzzado com cada payload da wordlist

- **Dado** uma URL com parâmetro marcado (ex.: `--param user`) e uma wordlist de payloads
- **Quando** o fuzzer roda
- **Então** cada payload é testado como valor do parâmetro e respostas distintas aparecem na saída

### US-042 — Modo s3 (buckets) no fuzzer

Como pentester, quero testar se nomes de bucket S3 existem e estão
expostos, para achar buckets públicos.

#### AC-077 — Bucket existente é detectado

- **Dado** um alvo S3 (ex.: `--s3`) com uma wordlist de nomes de bucket
- **Quando** o fuzzer roda
- **Então** buckets que respondem (existência confirmada) aparecem na saída com status

### US-043 — Fuzzing de DNS no fuzzer

Como pentester, quero fuzzar subdomínios via o fuzzer (estilo gobuster dns),
para descobrir hosts sem trocar de comando.

#### AC-078 — Subdomínios que resolvem aparecem na saída

- **Dado** um domínio e uma wordlist de subdomínios no modo dns
- **Quando** o fuzzer roda com `--dns <dominio>`
- **Então** os subdomínios que resolvem aparecem com o IP, e os que não resolvem são omitidos

## Fora de escopo

- NTLM sobre TCP puro (SMB) — apenas HTTP.
- Enumeração de objetos S3 (listar chaves) — apenas existência/status do bucket.
- DNS zone transfer via fuzzer (o comando `dns --axfr` já cobre).
- Fuzzing de headers além do `Host`/FUZZ existente.

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-026 | NTLM implementado para HTTP com NTLMv2 (handshake completo type1/2/3); NTLMv1 fica de fora por segurança | confirmada | Implementado NTLMv2 (type1/2/3) sobre HTTP |
| ASM-027 | Modo s3 testa `https://<bucket>.s3.amazonaws.com` e reporta existência por status HTTP (200/301/403 = existe; 404 = não) | confirmada | Implementado; 403 conta como existe/privado (decisão do dono do produto) |
| ASM-028 | Modo dns do fuzzer reusa o Resolver do recon (com --nameserver) — sem duplicar lógica | confirmada | Implementado reusando recon.Resolver |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-018 | No modo s3, bucket com 403 (privado) conta como "existe" ou é suprimido? | respondida | Aparece como existe/privado (200/301/403 = existe; 404 = não) — decisão do dono do produto |