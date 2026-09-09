package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nixteg/gofence/internal/recon"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/spf13/cobra"
)

var (
	portList     string
	portTop      int
	portUDP      bool
	portInputL   string
	portPing     bool
	portRetries  int
	portTimeoutS float64
	portXMLOut   string
	portSyn      bool
	portOSGuess  bool
)

// normalizeNmapFlags converte -iL/-oX (shorthands multi-char estilo nmap)
// em --iL/--oX antes do parse do pflag — o pflag só suporta shorthands de
// um caractere, então a tradução é feita manualmente nos args.
func normalizeNmapFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-iL":
			out = append(out, "--iL")
		case a == "-oX":
			out = append(out, "--oX")
		case strings.HasPrefix(a, "-iL="):
			out = append(out, "--iL="+strings.TrimPrefix(a, "-iL="))
		case strings.HasPrefix(a, "-oX="):
			out = append(out, "--oX="+strings.TrimPrefix(a, "-oX="))
		case strings.HasPrefix(a, "-iL") && len(a) > 3:
			// -iLvalor (sem espaço)
			out = append(out, "--iL="+a[3:])
		case strings.HasPrefix(a, "-oX") && len(a) > 3:
			out = append(out, "--oX="+a[3:])
		default:
			out = append(out, a)
		}
	}
	return out
}

var portCmd = &cobra.Command{
	Use:   "port <ip/cidr>",
	Short: "TCP/UDP port scanner",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var target string
	if len(args) > 0 || portInputL == "" {
		var err error
		target, err = stdinTarget(args)
		if err != nil {
			return err
		}
	}

	// -iL fornece a lista de alvos; o argumento posicional (ou stdin) soma-se.
	targets, err := resolvePortTargets(target, portInputL)
	if err != nil {
		return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no targets: pass <ip/cidr> or -iL <file>")
		}

		db, wsID := openWorkspace()
		for _, t := range targets {
			if err := requireScope(db, wsID, t, "port"); err != nil {
				if db != nil {
					db.Close()
				}
				return err
			}
		}

		timeout := time.Duration(portTimeoutS * float64(time.Second))
		scanner := recon.NewPortScanner(effConcurrency(), timeout)
		scanner.Retries = portRetries

		var ports []int
		if portList != "" {
			ports = parsePortList(portList)
		} else {
			ports = recon.TopPorts(portTop)
		}

		// Ping sweep primeiro: só varre hosts vivos quando pedido.
		if portPing {
			alive := scanner.PingSweep(targets, []int{80, 443, 22, 8080})
			if len(alive) == 0 {
				fmt.Fprintln(os.Stderr, "ping sweep: no live hosts found")
				return nil
			}
			fmt.Fprintf(os.Stderr, "ping sweep: %d live host(s)\n", len(alive))
			targets = alive
		}

		var results []recon.PortResult
		if portUDP {
			for _, t := range targets {
				results = append(results, scanner.ScanUDP(t, recon.TopUDPPorts(portTop))...)
			}
		} else if portSyn {
			synScanner := recon.NewSynScanner(effConcurrency(), timeout)
			for _, t := range targets {
				synResults, serr := synScanner.ScanSYN(t, ports)
				if serr != nil {
					return serr
				}
				results = append(results, synResults...)
			}
		} else {
			results = scanner.ScanTCPHosts(targets, ports)
		}

		// Fingerprint de SO sobre os hosts com portas abertas (sinais TCP).
		// O TTL/janela observados são inferidos por serviço (heuristicamente),
		// pois o Go não expõe o TTL do header IP via net.Conn.
		if portOSGuess {
			seenHosts := map[string]bool{}
			for _, r := range results {
				if r.State != "open" || r.Host == "" || seenHosts[r.Host] {
					continue
				}
				seenHosts[r.Host] = true
				ttl, win := guessSignals(r.Port)
				guess := recon.GuessOS(ttl, win, 1460)
				fmt.Printf("[os] %s: %s\n", r.Host, guess.String())
			}
		}

		// NSE-lite: scripts registrados rodam por serviço detectado.
		for _, r := range results {
			if r.Service == "" {
				continue
			}
			for _, sr := range recon.RunScripts(r.Host, r.Port, r.Service) {
				results = append(results, recon.PortResult{
					Host:    r.Host,
					Port:    r.Port,
					State:   "script",
					Service: sr.Service + "/" + sr.Name,
					Version: fmt.Sprintf("%v|%s", sr.OK, sr.Detail),
				})
			}
		}

		if portXMLOut != "" {
			if err := recon.WriteNmapXML(portXMLOut, results); err != nil {
				return fmt.Errorf("write -oX: %w", err)
			}
			fmt.Fprintf(os.Stderr, "XML written to %s\n", portXMLOut)
			return nil
		}

		if jsonOut {
			if err := ux.PrintJSON(results); err != nil {
				if db != nil {
					db.Close()
				}
				return err
			}
		} else {
			printPortResults(results)
		}

		if db != nil {
			persistPortResults(db, wsID, results)
			db.Close()
		}
		return nil
	},
}

// resolvePortTargets junta o alvo posicional com -iL, expandindo CIDRs.
func resolvePortTargets(arg, inputList string) ([]string, error) {
	var raw []string
	if inputList != "" {
		b, err := os.ReadFile(inputList)
		if err != nil {
			return nil, fmt.Errorf("read -iL file: %w", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				raw = append(raw, line)
			}
		}
	}
	if arg != "" {
		raw = append(raw, arg)
	}

	var targets []string
	for _, r := range raw {
		if strings.Contains(r, "/") {
			hosts, err := recon.ExpandCIDR(r)
			if err != nil {
				return nil, err
			}
			targets = append(targets, hosts...)
		} else {
			targets = append(targets, r)
		}
	}
	return targets, nil
}

func printPortResults(results []recon.PortResult) {
	for _, r := range results {
		if r.Host != "" {
			fmt.Printf("%s %d/%s %s", r.Host, r.Port, r.State, r.Service)
		} else {
			fmt.Printf("%d/%s %s", r.Port, r.State, r.Service)
		}
		if r.Version != "" {
			fmt.Printf(" (%s)", r.Version)
		}
		fmt.Println()
	}
}

func persistPortResults(db interface {
	HostUpsert(wsID int64, host, label string) (int64, error)
	PortUpsert(hostID int64, port int, service, state string) error
}, wsID int64, results []recon.PortResult) {
	seen := map[string]int64{}
	for _, r := range results {
		host := r.Host
		if host == "" {
			continue
		}
		hostID, ok := seen[host]
		if !ok {
			hid, err := db.HostUpsert(wsID, host, host)
			if err != nil {
				continue
			}
			hostID = hid
			seen[host] = hid
		}
		_ = db.PortUpsert(hostID, r.Port, r.Service, r.State)
	}
}

// guessSignals infere TTL/janela típicos a partir do serviço aberto —
// heurística para o --os-guess; o matcher puro (GuessOS) usa sinais reais
// quando medidos (trabalho futuro: raw socket expõe TTL do header IP).
func guessSignals(port int) (ttl, window int) {
	switch port {
	case 3389, 445, 139:
		return 128, 65535 // Windows típico
	case 22, 80, 443, 25, 53:
		return 64, 64240 // Linux/Unix típico
	default:
		return 64, 64240
	}
}

func parsePortList(s string) []int {
	var ports []int
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			var p int
			fmt.Sscanf(s[start:i], "%d", &p)
			if p > 0 {
				ports = append(ports, p)
			}
			start = i + 1
		}
	}
	return ports
}

func init() {
	portCmd.Flags().StringVar(&portList, "ports", "", "comma-separated port list")
	portCmd.Flags().IntVar(&portTop, "top", 1000, "scan top N common ports")
	portCmd.Flags().BoolVar(&portUDP, "udp", false, "scan UDP ports")
	// Shorthands estilo nmap: -iL e -oX são multi-caractere; o pflag não os
	// suporta nativamente, então normalizeNmapFlags os traduz em --iL/--oX
	// antes do parse (feito em cmd/root.go Execute).
	portCmd.Flags().StringVar(&portInputL, "iL", "", "file with one target per line (IPs or CIDRs)")
	portCmd.Flags().BoolVar(&portPing, "ping-sweep", false, "discover live hosts before scanning (TCP probe)")
	portCmd.Flags().IntVar(&portRetries, "retries", 0, "extra attempts per port before marking closed")
	portCmd.Flags().Float64Var(&portTimeoutS, "timeout", 2, "per-port dial timeout in seconds")
	portCmd.Flags().StringVar(&portXMLOut, "oX", "", "write nmap-compatible XML output to file")
	portCmd.Flags().BoolVar(&portSyn, "syn", false, "SYN scan (requires root/CAP_NET_RAW)")
	portCmd.Flags().BoolVar(&portOSGuess, "os-guess", false, "guess OS from TCP signals (TTL/window)")
	rootCmd.AddCommand(portCmd)
}