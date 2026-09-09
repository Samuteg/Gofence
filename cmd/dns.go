package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/assets"
	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/recon"
	"github.com/nixteg/gofence/internal/ux"
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
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := stdinTarget(args)
		if err != nil {
			return err
		}
		resolver := recon.NewResolver(effConcurrency())
		if dnsNS != "" {
			resolver.Nameserver = dnsNS
		}

		db, wsID := openWorkspace()
		guard, err := mustScope(db, wsID)
		if err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if !data.CheckHost(guard, domain, "dns") {
			db.Close()
			return fmt.Errorf("target %s is out of scope", domain)
		}

		if dnsAXFR {
			ns := dnsNS
			if ns == "" {
				ns = "8.8.8.8"
			}
			if !data.CheckHost(guard, ns, "axfr") {
				db.Close()
				return fmt.Errorf("target %s is out of scope", ns)
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

		var persisted int
		var inScope []recon.DNSResult
		for _, r := range results {
			if !data.CheckHost(guard, r.IP, "dns") {
				continue
			}
			fmt.Printf("%s %s\n", r.Subdomain, r.IP)
			inScope = append(inScope, r)
			if err := db.SaveFinding(wsID, r.IP, r.Subdomain, "info",
				"subdomain", fmt.Sprintf("domain=%s", domain)); err == nil {
				persisted++
			}
		}
		fmt.Fprintf(os.Stderr, "persisted %d subdomains to workspace\n", persisted)
		if jsonOut {
			if err := ux.PrintJSON(inScope); err != nil {
				db.Close()
				return err
			}
		}
		db.Close()
		return nil
	},
}

func init() {
	dnsCmd.Flags().StringVarP(&dnsWordlist, "wordlist", "w", "", "wordlist path for subdomain bruteforce (defaults to embedded list)")
	dnsCmd.Flags().BoolVar(&dnsAXFR, "axfr", false, "attempt zone transfer")
	dnsCmd.Flags().StringVar(&dnsNS, "nameserver", "", "nameserver for AXFR")
	rootCmd.AddCommand(dnsCmd)
}
