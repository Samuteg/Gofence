package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/recon"
	"github.com/spf13/cobra"
)

var (
	portList string
	portTop  int
	portUDP  bool
)

var portCmd = &cobra.Command{
	Use:   "port <ip/cidr>",
	Short: "TCP/UDP port scanner",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		scanner := recon.NewPortScanner(concur, 0)

		var ports []int
		if portList != "" {
			ports = parsePortList(portList)
		} else {
			ports = recon.TopPorts(portTop)
		}

		var results []recon.PortResult
		if portUDP {
			results = scanner.ScanUDP(target, recon.TopUDPPorts(portTop))
		} else {
			results = scanner.ScanTCP(target, ports)
		}

		for _, r := range results {
			fmt.Printf("%d/%s %s\n", r.Port, r.State, r.Service)
		}
		return nil
	},
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
	rootCmd.AddCommand(portCmd)
}
