# Spec: gofence-cli

> feature: gofence-cli
> status: rascunho

## Contexto

O gofence é um binário único em Go (statically linked) focado em pentest e reconhecimento de infraestrutura. Automatiza coleta de dados, descoberta de vulnerabilidades e exploração, com armazenamento local em SQLite e modos interativo (TUI) e headless (pipeline UNIX).

## Histórias

### US-001 — DNS em massa

Como pentester, quero resolver subdomínios em massa com brute-force e transferência de zona, para que eu descubra todos os ativos do alvo rapidamente.

#### AC-001 — brute-force de subdomínios

- **Dado** que o usuário fornece um domínio alvo e uma wordlist
- **Quando** executa `gofence dns <alvo> -w wordlist.txt`
- **Então** o binário resolve concorrentemente cada entrada da wordlist e imprime no STDOUT apenas subdomínios que existem, um por linha, com seu IP resolvido

#### AC-002 — transferência de zona

- **Dado** que o usuário fornece um domínio alvo
- **Quando** executa `gofence dns <alvo> --axfr`
- **Então** o binário tenta transferência de zona (AXFR) nos nameservers autoritativos e imprime todos os registros obtidos no STDOUT em formato JSON

#### AC-003 — concorrência configurável

- **Dado** que o usuário fornece o flag `--concurrency 500`
- **Quando** executa o comando DNS
- **Então** no máximo 500 goroutines resolvem simultaneamente, sem exceder o limite

### US-002 — OSINT via APIs externas

Como pentester, quero consultar Shodan, Censys e SecurityTrails para obter IPs, ports e leaks do alvo, integrando resultados ao fluxo de reconhecimento.

#### AC-004 — consulta Shodan

- **Dado** que a chave de API do Shodan está configurada via viper (env `GOFENCE_SHODAN_KEY`)
- **Quando** executa `gofence osint <alvo> --provider shodan`
- **Então** o binário consulta a API e imprime no STDOUT os IPs, portas e serviços encontrados em formato JSON

#### AC-005 — consulta multi-provider

- **Dado** que chaves de API para Shodan e Censys estão configuradas
- **Quando** executa `gofence osint <alvo> --provider all`
- **Então** o binário consulta todos os providers configurados e imprime resultado consolidado no STDOUT, agrupado por provider

### US-003 — Port scanning

Como pentester, quero varrer portas TCP/UDP em IPs do escopo, para identificar serviços ativos rapidamente.

#### AC-006 — varredura TCP rápida

- **Dado** que o usuário fornece um IP ou CIDR dentro do escopo
- **Quando** executa `gofence port <ip/cidr> --ports top1000`
- **Então** o binário escaneia assincronamente as portas dotop 1000 e imprime no STDOUT as portas abertas com serviço detectado, um por linha

#### AC-007 — varredura UDP

- **Dado** que o usuário fornece um IP dentro do escopo e o flag `--udp`
- **Quando** executa o comando port
- **Então** o binário escaneia portas UDP comuns (top 100) e imprime portas abertas ou com resposta

### US-004 — Fuzzer web de alta performance

Como pentester, quero fuzzar caminhos HTTP, cabeçalhos e dados POST com wordlists gigantes, para descobrir diretórios e endpoints ocultos.

#### AC-008 — fuzzing de caminhos

- **Dado** que o usuário fornece uma URL com `/FUZZ` e uma wordlist
- **Quando** executa `gofence fuzz web <url> -w wordlist.txt`
- **Então** o binário envia requisições HTTP para cada linha da wordlist substituindo `/FUZZ` e imprime no STDOUT as URLs que retornaram código HTTP diferente de 404, com status code e tamanho

#### AC-009 — fuzzing de cabeçalhos

- **Dado** que o usuário fornece uma URL e o flag `--header "Host: FUZZ"`
- **Quando** executa o comando fuzz
- **Então** o binário substitui `FUZZ` no cabeçalho por cada linha da wordlist e imprime respostas distintas

#### AC-010 — stream de wordlist (memória)

- **Dado** que a wordlist tem 10 milhões de entradas
- **Quando** executa o comando fuzz
- **Então** o binário lê a wordlist como stream (linha a linha) sem carregar tudo na RAM, mantendo uso de memória constante (< 50MB)

### US-005 — Análise TLS

Como pentester, quero verificar a cadeia de certificados e cifras suportadas, para identificar configurações inseguras.

#### AC-011 — inspeção de certificado

- **Dado** que o usuário fornece um host:porta
- **Quando** executa `gofence tls <host:porta>`
- **Então** o binário imprime no STDOUT o subject, issuer, datas de validade, fingerprint SHA-256 e cifras suportadas em formato JSON

#### AC-012 — detecção de TLS downgrade

- **Dado** que o servidor suporta TLS 1.0
- **Quando** executa o comando tls com `--strict`
- **Então** o binário lista como vulnerável qualquer protocolo abaixo de TLS 1.2

### US-006 — Crawler baseado em AST

Como pentester, quero rastrear páginas web extraindo links, endpoints ocultos e segredos, para mapear toda a superfície de ataque.

#### AC-013 — extração de links

- **Dado** que o usuário fornece uma URL inicial e profundidade máxima
- **Quando** executa `gofence crawl <url> --depth 3`
- **Então** o binário navega até a profundidade especificada e imprime no STDOUT todos os URLs encontrados, sem duplicatas

#### AC-014 — detecção de segredos

- **Dado** que a página contém tokens JWT, chaves AWS ou strings sensíveis
- **Quando** o crawler processa a página
- **Então** o binário imprime alerta no STDERR com tipo do segredo, arquivo-fonte e trecho encontrado (mascarado)

### US-007 — Templates de vulnerabilidade

Como pentester, quero executar templates YAML contra alvos para detectar CVEs conhecidas e falhas lógicas, de forma customizável.

#### AC-015 — execução de template

- **Dado** que existe um template YAML válido com request e matcher
- **Quando** executa `gofence vulns <alvo> -t template.yaml`
- **Então** o binário envia a requisição definida no template e compara a resposta com o regex/matcher, imprimindo no STDOUT se houve match com detalhes

#### AC-016 — execução em lote

- **Dado** que o usuário fornece um diretório com múltiplos templates
- **Quando** executa `gofence vulns <alvo> -t ./templates/`
- **Então** o binário executa todos os templates válidos e imprime apenas os que deram match

### US-008 — Gerador de payloads

Como pentester, quero gerar one-liners de conexão reversa/bind shell em Bash, PowerShell e Python, para operar rapidamente quando encontro uma vulnerabilidade.

#### AC-017 — payload reverso Bash

- **Dado** que o usuário fornece IP e porta
- **Quando** executa `gofence payload --type nc --ip <lhost> --port <lport>`
- **Então** o binário imprime no STDOUT um one-liner Bash de conexão reversa funcional

#### AC-018 — payload Python

- **Dado** que o usuário seleciona `--type python`
- **Quando** executa o comando payload
- **Então** o binário imprime um script Python de reverse shell no STDOUT

### US-009 — Multi-handler TCP/UDP

Como pentester, quero um servidor de escuta embutido que gerencie múltiplas sessões reversas simultâneas, com upgrade de TTY automático.

#### AC-019 — escuta e recepção

- **Dado** que o usuário inicia o handler na porta 4444
- **Quando** executa `gofence listen --port 4444`
- **Então** o binário aguarda conexões e ao receber uma, abre sessão interativa no terminal

#### AC-020 — múltiplas sessões

- **Dado** que o handler está rodando
- **Quando** duas conexões chegam simultaneamente
- **Então** o binário mantém ambas as sessões ativas e permite alternar entre elas

### US-010 — Engine de brute force

Como pentester, quero testar dicionários contra serviços SSH, FTP e HTTP Basic, para identificar credenciais fracas.

#### AC-021 — brute force SSH

- **Dado** que o usuário fornece alvo, usuário e wordlist de senhas
- **Quando** executa `gofence brute ssh <alvo> -u admin -w passwords.txt`
- **Então** o binário tenta autenticar sequencialmente cada senha e imprime no STDOUT quando encontrar credencial válida

#### AC-022 — brute force HTTP Basic

- **Dado** que o usuário fornece URL de login
- **Quando** executa `gofence brute http <url> -u admin -w passwords.txt`
- **Então** o binário envia requisições com Basic Auth e detecta login bem-sucedido por mudança de status/cookie

### US-011 — Banco de dados SQLite

Como pentester, quero que todos os dados coletados sejam persistidos localmente em SQLite, com workspaces separados por engajamento.

#### AC-023 — criação de workspace

- **Dado** que o usuário cria um novo engajamento
- **Quando** executa `gofence workspace new "Cliente X"`
- **Então** o binário cria entrada na tabela `workspaces` com timestamp e imprime o ID gerado

#### AC-024 — persistência de hosts

- **Dado** que o recon identificou hosts
- **Quando** o resultado é salvo
- **Então** o binário insere na tabela `hosts` com IP, hostname e workspace_id, sem duplicatas

#### AC-025 — persistência de findings

- **Dado** que um template de vulnerabilidade encontrou match
- **Quando** o resultado é registrado
- **Então** o binário insere na tabela `findings` com host_id, severity, título e dados JSON da evidência

### US-012 — Scope guard

Como pentester, quero que toda operação de rede verifique o escopo antes de executar, para evitar testes fora do contratado.

#### AC-026 — bloqueio de IP fora do escopo

- **Dado** que o workspace tem CIDR 10.0.0.0/8 como permitido
- **Quando** uma operação tenta acessar 192.168.1.1
- **Então** o binário descarta a operação internamente e registra log `Out-of-Scope Blocked` no STDERR, sem enviar pacote à rede

#### AC-027 — liberação de IP dentro do escopo

- **Dado** que o workspace tem CIDR 10.0.0.0/8 como permitido
- **Quando** uma operação acessa 10.0.1.5
- **Então** o binário permite a operação normalmente

### US-013 — Modo interativo (TUI)

Como pentester, quero um dashboard no terminal com painéis de hosts ativos, sessões de shell e progresso de varreduras em tempo real, para monitorar o ataque.

#### AC-028 — dashboard principal

- **Dado** que o usuário executa `gofence`
- **Quando** o binário inicia sem subcomando
- **Então** exibe TUI com painéis: hosts descobertos, portas abertas, sessões ativas e log de atividades

#### AC-029 — atualização em tempo real

- **Dado** que uma varredura está em andamento
- **Quando** novos hosts são descobertos
- **Então** a TUI atualiza o painel de hosts automaticamente sem flash/flicker

### US-014 — Modo headless/pipeline

Como pentester, quero operar via flags com saída canalizável (pipe), para integrar com ferramentas UNIX como jq e grep.

#### AC-030 — saída JSON canalizável

- **Dado** que o usuário executa `gofence dns alvo.com | jq '.subdomains'`
- **Quando** o comando roda em modo headless
- **Então** o STDOUT contém apenas JSON puro (sem logs, sem banners), e o STDERR contém progresso

#### AC-031 — encadeamento de comandos

- **Dado** que o usuário executa `gofence dns alvo.com | gofence port`
- **Quando** o pipe conecta saída de um comando à entrada do outro
- **Então** o segundo comando recebe os IPs do primeiro como alvo automaticamente

### US-015 — Rate limiting inteligente

Como pentester, quero perfis de evasão de rate limit (Sneaky, Normal, Aggressive) para adaptar a velocidade ao alvo.

#### AC-032 — perfil Sneaky

- **Dado** que o usuário seleciona `--rate sneaky`
- **Quando** executa qualquer comando de rede
- **Então** o binário limita a 1 requisição por segundo

#### AC-033 — perfil Normal

- **Dado** que o usuário seleciona `--rate normal` (ou padrão)
- **Quando** executa comando de rede
- **Então** o binário limita a 50 requisições por segundo

#### AC-034 — perfil Aggressive

- **Dado** que o usuário seleciona `--rate aggressive`
- **Quando** executa comando de rede
- **Então** o binário não aplica limite lógico, usando apenas resources do SO

## Fora de escopo

- Exploits zero-day ou payloads ofensivos armazenados na CLI
- Integração com frameworks de exploit (Metasploit, etc.)
- Modo gráfico (GUI) — apenas TUI e CLI
- Coleta de credenciais de APIs de terceiros (apenas uso com chave já obtida)
- Automação de pivoteamento em redes internas

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-001 | Go 1.22+ estará disponível no ambiente de compilação | confirmada | Go 1.26.5 usado na implementação |
| ASM-002 | As APIs do Shodan/Censys/SecurityTrails são acessíveis a partir da rede do pentester | aberta | Depende do ambiente do usuário |
| ASM-003 | O binário roda em Linux (amd64/arm64); suporte a Windows/macOS é futuro | aberta | Build testado em linux/amd64 |
| ASM-004 | A wordlist de DNS padrão (top 1M) será embutida ou referenciada por caminho | confirmada | Referenciada via flag `-w` |
| ASM-005 | O SQLite local fica no diretório atual ou em ~/.gofence/ | confirmada | `~/.gofence/gofence.db` (flag `--db` override) |
| ASM-006 | O TUI funciona apenas em terminais com suporte a ANSI (256 cores, unicode) | confirmada | Bubbletea + Lipgloss |
| ASM-007 | O handler de sessões não precisa de elevação (root) para portas altas (>1024) | confirmada | Portas >1024 funcionam sem root |
| ASM-008 | A validação de escopo consulta o SQLite do workspace ativo | confirmada | ScopeGuard consulta tabela `scope` |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-001 | Qual banco de dados local padrão? O spec diz SQLite, mas precisa confirmar se modernc.org/sqlite (pure Go) ou CGO sqlite3 | respondida | modernc.org/sqlite (pure Go, binário estático, sem CGO) |
| Q-002 | O brute force deve ter proteção contra lockout (max tentativas por minute)? | respondida | Sim — backoff exponencial após 5 falhas; flag `--no-backoff` desativa |
| Q-003 | O crawl deve respetar robots.txt ou ignorar para pentest? | respondida | Ignorar robots.txt (pentest ofensivo) |
| Q-004 | Os templates de vulnerabilidade devem seguir formato de alguma ferramenta existente (Nuclei, etc.) ou formato próprio? | respondida | Formato compatível com Nuclei (YAML: requests[], matchers[]) |
| Q-005 | O multi-handler deve suportar payload encriptado/encodado na recepção? | respondida | Sim — decode Base64/XOR na recepção |
| Q-006 | Qual o comportamento quando a API do OSINT retorna erro 429 (rate limit)? Retry com backoff ou falha imediata? | respondida | Retry com exponential backoff (3 tentativas); falha com mensagem se persistir |
| Q-007 | O workspace deve suportar deleção lógica (soft delete) ou física? | respondida | Soft delete (coluna `deleted_at`) |
| Q-008 | O modo pipeline deve ter flag `--json` explícito ou detectar automaticamente quando stdout não é um terminal? | respondida | Ambos — `--json` explícito tem prioridade; auto-detect isatty no stdout |
