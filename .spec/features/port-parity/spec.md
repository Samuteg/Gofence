# Spec: Port parity

> feature: port-parity
> status: rascunho

## Contexto

O scanner de portas (`gofence port`) resolve o básico com connect scan, mas
fica muito aquém do nmap: o README promete varredura de CIDR que o código não
faz (o endereço é passado literal ao `net.Dial`), não identifica serviço nem
versão (mapa estático porta→nome), só conhece uma técnica de scan, não
descobre hosts vivos, não detecta SO, não suporta IPv6 (erro conhecido de
formatação no `go vet`), não tem retries nem controle fino de timing, não
aceita lista de alvos, não roda scripts por serviço e não exporta XML
compatível. Esta feature entrega paridade prática com o nmap para o uso
contratado da ferramenta.

## Histórias

### US-019 — Varredura de CIDR que funciona de verdade

Como pentester que recebe um bloco contratado (ex.: 10.0.0.0/24), quero que
`gofence port 10.0.0.0/24` varra cada host da faixa, para não precisar
enumerar IP por IP.

#### AC-046 — Alvo em CIDR é expandido e cada host é varrido

- **Dado** um alvo em notação CIDR (ex.: 127.0.0.1/31) e uma porta aberta em um dos hosts da faixa
- **Quando** o scanner roda contra o CIDR
- **Então** cada endereço da faixa é varrido e a porta aberta aparece associada ao IP correto (não ao literal do CIDR)

#### AC-049 — Resultado por host individual

- **Dado** um CIDR com pelo menos dois hosts, um deles sem portas abertas
- **Quando** a varredura termina
- **Então** a saída lista cada host com suas portas abertas (o host sem portas não é listado como aberto)

### US-022 — Identificação de serviço e versão (banner grabbing)

Como pentester, quero saber qual serviço e versão rodam numa porta aberta,
para priorizar exploração sem depender do mapa estático.

#### AC-050 — Banner identificado vira serviço+versão no resultado

- **Dado** uma porta aberta cujo serviço responde um banner (ex.: "SSH-2.0-OpenSSH_8.9p1")
- **Quando** o scanner coleta o banner
- **Então** o resultado carrega o serviço (ssh) e a versão (8.9p1) identificados a partir do banner

#### AC-051 — Serviço sem banner cai no mapa estático como fallback

- **Dado** uma porta aberta que não responde banner no tempo limite
- **Quando** o scanner tenta identificar o serviço
- **Então** o resultado mantém o nome do mapa estático (ex.: 3306 → mysql) e versão vazia, sem erro

### US-023 — SYN scan (stealth)

Como pentester autorizado, quero varrer portas com SYN scan (-sS), para
reduzir o rastro de conexões completas e obter estado mais preciso em hosts
com firewall.

#### AC-052 — SYN scan reporta porta aberta

- **Dado** uma porta TCP aberta escutando em localhost
- **Quando** o SYN scan roda com privilégio suficiente contra essa porta
- **Então** a porta é reportada como aberta

#### AC-053 — Sem privilégio, erro claro pedindo root

- **Dado** um ambiente sem CAP_NET_RAW (usuário comum)
- **Quando** o SYN scan tenta abrir o socket raw
- **Então** o comando falha com mensagem orientando a rodar como root/sudo ou usar connect scan, sem travar

### US-024 — Descoberta de host (ping sweep)

Como pentester, quero descobrir quais hosts de uma faixa estão vivos antes da
varredura de portas, para economizar tempo e reduzir ruído.

#### AC-054 — Hosts vivos da faixa são listados

- **Dado** uma faixa de IPs onde apenas alguns hosts respondem a um probe TCP (ex.: porta 80/443)
- **Quando** o ping sweep roda contra a faixa
- **Então** a saída lista apenas os hosts que responderam, com o IP individual

### US-025 — Detecção de SO por fingerprint TCP

Como pentester, quero um palpite do sistema operacional do host, para ajustar
a exploração.

#### AC-055 — Fingerprint TCP produz palpite de SO

- **Dado** um host cujas respostas TCP casam com uma assinatura do banco embutido
- **Quando** a detecção de SO roda após a varredura
- **Então** a saída traz o nome do SO provável (ex.: "Linux") ou "desconhecido" quando nenhuma assinatura casa

### US-026 — Timing e retries configuráveis

Como pentester, quero controlar retries e taxa mínima de scan, para varreduras
lentas não marcarem portas como fechadas por timeout e para respeitar limites
do alvo.

#### AC-056 — Retry em timeout antes de marcar fechada

- **Dado** um host que descarta pacotes (drop) na primeira tentativa
- **Quando** a varredura roda com retries configurados
- **Então** a porta não é marcada como fechada na primeira falha: as tentativas configuradas são esgotadas antes do veredito

### US-027 — Suporte a IPv6

Como pentester em redes IPv6, quero varrer alvos IPv6 literais sem erro de
formatação.

#### AC-057 — Alvo IPv6 literal é varrido sem erro

- **Dado** um alvo IPv6 literal (ex.: ::1) e uma porta aberta nele
- **Quando** o scanner roda contra o endereço
- **Então** o scan executa sem erro de endereço e reporta a porta aberta corretamente

### US-028 — Lista de alvos (-iL)

Como pentester, quero varrer vários alvos de uma vez a partir de um arquivo,
para automatizar o reconhecimento em massa.

#### AC-058 — Alvos de arquivo são varridos um a um

- **Dado** um arquivo com vários alvos (IPs ou hosts) na flag -iL
- **Quando** a varredura roda
- **Então** cada alvo é varrido e a saída agrupa os resultados por host

### US-029 — NSE-lite: scripts por serviço

Como pentester, quero que scripts Go registrados rodem automaticamente
conforme o serviço detectado (banner multi-proto, checagens por protocolo),
para extrair informações sem abrir outra ferramenta.

#### AC-059 — Script registrado roda para o serviço detectado

- **Dado** um script Go registrado para um serviço (ex.: ssh) no framework
- **Quando** a varredura identifica esse serviço numa porta aberta
- **Então** o script executa e seu resultado aparece na saída da varredura

#### AC-060 — Checagem por protocolo executa e reporta

- **Dado** uma porta aberta de um protocolo com checagem implementada (ex.: DNS em 53/UDP ou SMTP em 25/TCP)
- **Quando** a varredura termina
- **Então** a checagem do protocolo roda e o resultado (ok/falha/detalhe) é reportado

### US-030 — Saída XML compatível com nmap (-oX)

Como pentester, quero exportar o resultado em XML no formato -oX do nmap,
para alimentar ferramentas que consomem esse formato (Metasploit, Faraday...).

#### AC-061 — -oX gera XML compatível com nmap

- **Dado** uma varredura concluída com a flag -oX apontando para um arquivo
- **Quando** o comando termina
- **Então** o arquivo contém XML com estrutura compatível ao nmap (nmaprun com host/ports), legível por parser padrão de -oX

## Fora de escopo

- Detecção de SO por fingerprint completo estilo nmap com banco gigante — o
  banco embutido cobre SOs comuns (Linux, Windows, macOS, BSD, roteadores),
  decidido com o dono do produto.
- Scripts Lua como no NSE do nmap — aqui os scripts são Go registrados em
  código, decidido com o dono do produto.
- Scan idle, FTP bounce, decoy/spoof — técnicas de evasão avançadas ficam de
  fora desta feature.
- Traceroute e path MTU discovery.
- Varredura SCTP.

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-015 | SYN scan exige privilégio; em ambiente de teste sem root, os testes cobrem o caminho de erro (AC-053) e a lógica de parse, não o socket real | aberta | A confirmar na execução — testes herméticos usam abstração injetável |
| ASM-016 | Banco de assinaturas de SO embutido no binário cobre SOs comuns; assinaturas derivadas de fingerprints públicos documentados | aberta | Decisão do dono do produto: embutido |
| ASM-017 | XML -oX segue o DTD público do nmap para os campos host/address/ports; campos não preenchidos pelo gofence ficam omitidos | aberta | Decisão do dono do produto: compatível com nmap |
| ASM-018 | Banner grabbing é não-destrutivo: envia probe simples e lê a resposta inicial; sem handshakes de protocolo completos | aberta | A confirmar na execução |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-012 | Quais checagens por protocolo implementar primeiro (DNS, SMTP, SNMP, SMB...)? | aberta | — |
| Q-013 | Retry padrão: qual valor default (0 = sem retry, mantendo o comportamento atual)? | aberta | — |