# Tasks: NSE SNMP/SMB

> feature: nse-snmp-smb

## T-049 — Script SNMP (sysDescr) [concluida]
- Refs: US-039, AC-072
- Arquivos: internal/recon/scripts_snmp.go, internal/recon/scripts_snmp_test.go
- Esforço: alto
- Notas: pacote SNMPv2c GET sysDescr (1.3.6.1.2.1.1.1.0) sobre UDP, parse da resposta BER; comunidade "public"; registra sob "snmp"; teste hermético com servidor UDP fake em memória

## T-050 — Script SMB (negotiate dialect) [concluida]
- Refs: US-039, AC-073
- Arquivos: internal/recon/scripts_smb.go, internal/recon/scripts_smb_test.go
- Esforço: alto
- Notas: SMB2 negotiate request mínimo, parse da resposta para dialect; registra sob "microsoft-ds"/"smb"; teste hermético com listener TCP fake