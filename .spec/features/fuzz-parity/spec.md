# Spec: Fuzz parity

> feature: fuzz-parity
> status: rascunho

## Contexto

O fuzzer web (`gofence fuzz`) já faz streaming de wordlist, WAF backoff e
rate limit, mas fica aquém do gobuster: não detecta página curinga
(wildcard/catch-all) que responde 200 para tudo (falsos positivos em massa),
não filtra por tamanho de resposta nem por whitelist de status, não recorre em
diretórios descobertos, não anexa extensões automaticamente, não tem modo
vhost dedicado, não usa robots.txt/sitemap como fonte de paths, não retoma
sessão interrompida e não aplica auth/cookies/User-Agent via CLI. Esta feature
entrega paridade prática com o gobuster para o uso contratado da ferramenta.

## Histórias

### US-020 — Detecção de wildcard/catch-all no fuzzer HTTP

Como pentester, quero que o fuzzer detecte quando o alvo responde 200 para
qualquer caminho (página curinga), para não reportar milhares de falsos
positivos.

#### AC-047 — Respostas curinga são detectadas e descartadas

- **Dado** um servidor que responde 200 com o mesmo corpo para qualquer path
- **Quando** o fuzzer roda contra ele
- **Então** a saída não lista as respostas curinga como achados e um aviso de
  wildcard detectado vai para o STDERR

#### AC-062 — Filtro por tamanho de resposta

- **Dado** um alvo cujas respostas de erro têm tamanho fixo (ex.: 404 genérico com corpo padrão)
- **Quando** o fuzzer roda com `--exclude-length` apontando para esse tamanho
- **Então** respostas com esse tamanho são suprimidas da saída, mesmo com status ≠ 404

### US-031 — Filtro por whitelist de status

Como pentester, quero exibir apenas os códigos de status que me interessam
(ex.: 200, 204, 301), para reduzir ruído em alvos que respondem 403 para tudo.

#### AC-063 — Apenas os status da whitelist aparecem

- **Dado** um alvo que responde 403 na maioria dos paths e 200 em alguns
- **Quando** o fuzzer roda com `--status-codes 200,301`
- **Então** apenas respostas 200/301 são exibidas na saída

### US-032 — Recursão em diretórios descobertos

Como pentester, quero que o fuzzer desça nos diretórios que encontrar (modo
`-r` do gobuster), para mapear a árvore inteira sem rodar o comando de novo.

#### AC-064 — Diretório descoberto é re-fuzado recursivamente

- **Dado** um alvo com `/admin/` respondendo 200 e `/admin/config` existindo
- **Quando** o fuzzer roda com `--recursive` (e profundidade)
- **Então** a saída inclui achados dentro de `/admin/` além do próprio `/admin`

### US-033 — Extensões automáticas (-x)

Como pentester, quero anexar extensões a cada palavra da wordlist (ex.:
`-x php,html`), para descobrir `index.php`, `index.html` sem wordlist duplicada.

#### AC-065 — Cada palavra é testada com cada extensão

- **Dado** uma wordlist com a palavra `index` e a flag `-x php,html`
- **Quando** o fuzzer roda
- **Então** `index.php` e `index.html` são testados e os que respondem aparecem na saída

### US-034 — Modo vhost dedicado

Como pentester, quero fuzzing de vhosts (cabeçalho Host) com filtro de
respostas idênticas à base, para descobrir vhosts virtuais sem ruído.

#### AC-066 — Vhosts distintos aparecem, respostas iguais à base são filtradas

- **Dado** um servidor virtual que responde conteúdo diferente para um Host específico
- **Quando** o fuzzer roda com `--vhost` sobre uma wordlist de nomes
- **Então** o vhost com resposta distinta aparece na saída e os Hosts que
  devolvem o mesmo conteúdo da base são suprimidos

### US-035 — robots.txt/sitemap como fonte de paths

Como pentester, quero que o fuzzer use robots.txt/sitemap.xml como semente de
paths quando disponíveis, para achar rotas não óbvias.

#### AC-067 — Paths de robots/sitemap entram no fuzz

- **Dado** um alvo com robots.txt contendo `Disallow: /admin/`
- **Quando** o fuzzer roda com `--robots` (ou sitemap)
- **Então** `/admin/` é testado e, se responder, aparece na saída

### US-036 — Retomada de sessão (resume)

Como pentester, quero salvar o progresso do fuzz e retomar de onde parou após
interrupção, para não repetir o trabalho numa wordlist gigante.

#### AC-068 — Sessão interrompida é retomada do ponto salvo

- **Dado** um fuzz em andamento salvo em arquivo de estado (`-o`) e interrompido
- **Quando** o fuzzer roda novamente com `--resume <estado>`
- **Então** ele continua das palavras ainda não testadas, sem repetir as já concluídas

### US-037 — Auth, cookies e User-Agent via CLI

Como pentester, quero aplicar credenciais Basic/NTLM, cookies e User-Agent
customizado no fuzzer, para testar áreas autenticadas.

#### AC-069 — Credenciais, cookie e UA são enviados na requisição

- **Dado** um alvo que só responde 200 com `Authorization: Basic ...` ou cookie específico
- **Quando** o fuzzer roda com flags `--auth`, `--cookie` e `--user-agent`
- **Então** as requisições carregam esses valores e a resposta 200 aparece na saída

## Fora de escopo

- Fuzzing de S3 buckets (modo `s3` do gobuster) — fica para trabalho futuro.
- Fuzzing de DNS no fuzzer web (o comando `dns` já cobre).
- Parse completo de sitemap com namespaces — apenas URLs diretas de
  `<loc>`/`Disallow:`.
- Fuzzing de parâmetros GET/POST com payloads (isso é o `--data` existente;
  não entra mutação de payload nesta feature).

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-019 | Wildcard é detectado por uma requisição de referência com path aleatório; respostas com mesmo status+size da referência são descartadas | aberta | A confirmar na execução — espelha a lógica já existente no DNS |
| ASM-020 | Recursão é BFS limitada por profundidade máxima (flag), com deduplicação de URLs já visitadas | aberta | A confirmar na execução |
| ASM-021 | Estado de resume é um arquivo JSON no caminho dado por `-o`/`--resume`, versionado simples (palavra atual + achados) | aberta | A confirmar na execução |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-014 | Profundidade padrão da recursão e limite máximo de URLs por diretório? | aberta | — |
| Q-015 | Auth: apenas Basic ou também Bearer/NTLM via flag separada? | aberta | — |