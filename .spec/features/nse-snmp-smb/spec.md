# Spec: NSE SNMP/SMB

> feature: nse-snmp-smb
> status: rascunho

## Contexto

O framework NSE-lite (`internal/recon/scripts.go`) já tem scripts para SSH,
DNS e SMTP (feature port-parity). As perguntas respondidas naquela feature
(Q-012) deixaram SNMP e SMB explícitos como trabalho futuro: são dois dos
serviços mais comuns em redes internas e hoje o scanner os identifica mas
não extrai informação. Esta feature adiciona checagens SNMP (UDP 161) e SMB
(TCP 445) não-destrutivas.

## Histórias

### US-039 — Checagens SNMP e SMB no NSE-lite

Como pentester, quero que scripts Go registrados rodem contra serviços SNMP
e SMB detectados, para extrair descrição do dispositivo (SNMP) e dialect
SMB (SMB) sem abrir outra ferramenta.

#### AC-072 — Checagem SNMP extrai a descrição do dispositivo

- **Dado** um serviço SNMP (UDP 161) respondendo a uma query GET com sysDescr
- **Quando** o script SNMP roda contra o host/porta
- **Então** o resultado reporta OK com a descrição do dispositivo (ex.: o nome do fabricante/modelo)

#### AC-073 — Checagem SMB reporta o dialect negociado

- **Dado** um serviço SMB (TCP 445) respondendo a um negotiate request
- **Quando** o script SMB roda contra o host/porta
- **Então** o resultado reporta OK com o dialect SMB (ex.: SMB 2.1 / SMB 3.1.1) ou falha clara quando não negocia

## Fora de escopo

- Enumeração completa de shares SMB, RID brute force ou coleta de usuários.
- SNMP walk completo do MIB — apenas sysDescr (1.3.6.1.2.1.1.1.0).
- Autenticação SMB (session setup) — apenas o negotiate inicial não-destrutivo.
- Comunidades SNMP além de "public".

## Suposições

| ID | Suposição | Status | Resolução |
|---|---|---|---|
| ASM-024 | A checagem SNMP usa o pacote padrão (comunidade "public", GET sysDescr) e considera resposta com erro SNMP como falha não-destrutiva | confirmada | Implementado; v2c com fallback v1 (decisão do dono do produto) |
| ASM-025 | A checagem SMB envia apenas o negotiate request (SMB2) e lê a resposta; sem session setup | confirmada | Implementado; apenas negotiate, sem session setup |

## Perguntas em aberto

| ID | Pergunta | Status | Resposta |
|---|---|---|---|
| Q-017 | SNMPv1 ou SNMPv2c no probe? (v2c adiciona mais alvos modernos, v1 cobre legado) | respondida | Ambas com fallback: tenta v2c, se falhar tenta v1 — decisão do dono do produto |