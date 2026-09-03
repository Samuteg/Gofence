package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/assets"
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

		if dnsWordlist == "" {
			if assets.HasWordlist("subdomains.txt") {
				words, werr := assets.Wordlist("subdomains.txt")
				if werr != nil {
					return werr
				}
				f, err := writeTempWordlist(words, "subdomains")
				if err != nil {
					return err
				}
				defer os.Remove(f)
				dnsWordlist = f
				fmt.Fprintln(os.Stderr, "no -w given; using embedded subdomain wordlist")
			} else {
				return fmt.Errorf("wordlist required (-w)")
			}
		}

		results, err := resolver.BruteForce(domain, dnsWordlist)
		if err != nil {
			return fmt.Errorf("bruteforce: %w", err)
		}

		db, wsID := openWorkspace()
		var persisted int
		for _, r := range results {
			fmt.Printf("%s %s\n", r.Subdomain, r.IP)
			if db != nil {
				if err := db.SaveFinding(wsID, r.IP, r.Subdomain, "info",
					"subdomain", fmt.Sprintf("domain=%s", domain)); err == nil {
					persisted++
				}
			}
		}
		if db != nil {
			fmt.Fprintf(os.Stderr, "persisted %d subdomains to workspace\n", persisted)
			db.Close()
		}
		return nil
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsWordlist, "wordlist", "w", "", "wordlist path for subdomain bruteforce (defaults to embedded list)")
	dnsCmd.Flags().BoolVar(&dnsAXFR, "axfr", false, "attempt zone transfer")
	dnsCmd.Flags().StringVar(&dnsNS, "nameserver", "", "nameserver for AXFR")
	rootCmd.AddCommand(dnsCmd)
}
