# Tasks: Port parity

> feature: port-parity

## T-028 — Expandir CIDR no port scan [concluida]
- Refs: US-019, AC-046, AC-049
- Arquivos: internal/recon/portscan.go, cmd/port.go
- Esforço: medio
- Notas: expandir alvo CIDR em lista de IPs (net.ParseCIDR + iterar hosts), varrer cada host e rotular resultados com o IP; saída por host

## T-029 — Banner grabbing e detecção de versão [concluida]
- Refs: US-022, AC-050, AC-051
- Arquivos: internal/recon/portscan.go
- Esforço: alto
- Notas: após porta aberta, conectar e ler banner inicial com deadline; regex por serviço (SSH, HTTP Server, FTP, SMTP...) extrai nome+versão; sem banner → fallback mapa estático com versão vazia

## T-030 — SYN scan com raw socket [concluida]
- Refs: US-023, AC-052, AC-053
- Arquivos: internal/recon/synscan.go, go.mod
- Modelo: claude-sonnet-5
- Esforço: xalto
- Notas: SYN scan via gopacket (raw socket, privilégio); sem CAP_NET_RAW → erro claro orientando root/connect scan; modo injectable para testes herméticos (AC-053 cobre caminho de erro; AC-052 em ambiente com privilégio ou mock)

## T-031 — Ping sweep / descoberta de host [concluida]
- Refs: US-024, AC-054
- Arquivos: internal/recon/hostdiscovery.go, cmd/port.go
- Esforço: medio
- Notas: probe TCP em portas comuns (80/443) por host da faixa; lista hosts vivos com IP individual

## T-032 — Fingerprint de SO embutido [concluida]
- Refs: US-025, AC-055
- Arquivos: internal/recon/osfingerprint.go, internal/assets/os-fingerprints.yaml, internal/assets/assets.go
- Esforço: alto
- Notas: banco embutido de assinaturas (TTL inicial, janela TCP, opções, MSS) para Linux/Windows/macOS/BSD/roteadores; matcher retorna nome ou "desconhecido"

## T-033 — Timing e retries configuráveis [concluida]
- Refs: US-026, AC-056
- Arquivos: internal/recon/portscan.go, cmd/port.go
- Esforço: medio
- Notas: flag --retries e --timeout; porta só marcada fechada após esgotar tentativas; default mantém comportamento atual (sem retry)

## T-034 — Suporte a IPv6 [concluida]
- Refs: US-027, AC-057
- Arquivos: internal/recon/portscan.go
- Esforço: baixo
- Notas: endereço IPv6 literal (ex.: ::1) formatado com colchetes no alvo (net.JoinHostPort); corrige aviso do go vet

## T-035 — Lista de alvos -iL [concluida]
- Refs: US-028, AC-058
- Arquivos: cmd/port.go, cmd/helpers.go
- Esforço: medio
- Notas: flag -iL lê arquivo com um alvo por linha; varre cada alvo e agrupa saída por host

## T-036 — Framework de scripts Go (NSE-lite) [concluida]
- Refs: US-029, AC-059, AC-060
- Arquivos: internal/recon/scripts.go, internal/recon/scripts_ssh.go, internal/recon/scripts_dns.go, internal/recon/scripts_smtp.go, cmd/port.go
- Modelo: claude-sonnet-5
- Esforço: xalto
- Notas: registro de scripts por serviço; banner multi-proto; checagens por protocolo (DNS 53, SMTP 25, SSH 22); resultado anexado à saída da varredura

## T-037 — Saída XML compatível com nmap -oX [concluida]
- Refs: US-030, AC-061
- Arquivos: internal/recon/xml.go, cmd/port.go
- Esforço: medio
- Notas: flag -oX <arquivo>; estrutura nmaprun/host/address/ports; parseável por ferramentas que consomem -oX; omitir campos não preenchidos