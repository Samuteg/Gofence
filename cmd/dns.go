package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/nixteg/gofence/internal/recon"
	"github.com/spf13/cobra"
)

var (
	dnsWordlist string
	dnsAXFR     bool
	dnsNS       string
)

var dnsCmd = &cobra.Command{
	Use:   "dns <alvo>",
	Short: "DNS brute-force and zone transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		resolver := recon.NewResolver(concur)

		if dnsAXFR {
			ns := dnsNS
			if ns == "" {
				ns = "8.8.8.8"
			}
			records, err := resolver.AXFR(domain, ns)
			if err != nil {
				return fmt.Errorf("axfr: %w", err)
			}
			out, _ := json.MarshalIndent(records, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		results, err := resolver.BruteForce(domain, dnsWordlist)
		if err != nil {
			return fmt.Errorf("bruteforce: %w", err)
		}
		for _, r := range results {
			fmt.Printf("%s %s\n", r.Subdomain, r.IP)
		}
		return nil
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsWordlist, "wordlist", "w", "", "wordlist path for subdomain bruteforce")
	dnsCmd.Flags().BoolVar(&dnsAXFR, "axfr", false, "attempt zone transfer")
	dnsCmd.Flags().StringVar(&dnsNS, "nameserver", "", "nameserver for AXFR")
	rootCmd.AddCommand(dnsCmd)
}
