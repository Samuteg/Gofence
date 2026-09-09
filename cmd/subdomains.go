package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/assets"
	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/spf13/cobra"
)

var (
	// Flags próprias do comando (não mutam globals do fuzz).
	subNameserver string
	subWordlist   string
)

var subdomainsCmd = &cobra.Command{
	Use:   "subdomains <domain>",
	Short: "Resolve subdomains from a wordlist (gobuster dns style)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := stdinTarget(args)
		if err != nil {
			return err
		}

		wordlist, cleanup, err := resolveSubWordlist(subWordlist)
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}

		db, wsID := openWorkspace()
		guard, err := mustScope(db, wsID)
		if err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if !data.CheckHost(guard, domain, "subdomains") {
			db.Close()
			return fmt.Errorf("target %s is out of scope", domain)
		}

		resolved, err := surface.FuzzDNSContext(Ctx(), effConcurrency(), domain, wordlist, subNameserver)
		if err != nil {
			db.Close()
			return err
		}

		persisted := 0
		var inScope []surface.DNSFuzzResult
		for _, r := range resolved {
			if !data.CheckHost(guard, r.IP, "subdomains") {
				continue
			}
			fmt.Printf("%s %s\n", r.Subdomain, r.IP)
			inScope = append(inScope, r)
			if db != nil {
				if err := db.SaveFinding(wsID, r.IP, r.Subdomain, "info",
					"subdomain", fmt.Sprintf("domain=%s", domain)); err == nil {
					persisted++
				}
			}
		}
		fmt.Fprintf(os.Stderr, "persisted %d subdomains to workspace\n", persisted)
		if jsonOut {
			if err := ux.PrintJSON(inScope); err != nil {
				if db != nil {
					db.Close()
				}
				return err
			}
		}
		if db != nil {
			db.Close()
		}
		return nil
	},
}

// resolveSubWordlist resolve a wordlist de subdomínios: -w explícita (via
// wlPath) ou a wordlist embutida subdomains.txt como fallback (mesma política
// do dns). Retorna (path, cleanup, error).
func resolveSubWordlist(wlPath string) (string, func(), error) {
	if wlPath != "" {
		return wlPath, nil, nil
	}
	if assets.HasWordlist("subdomains.txt") {
		words, err := assets.Wordlist("subdomains.txt")
		if err != nil {
			return "", nil, err
		}
		f, err := writeTempWordlist(words, "subdomains")
		if err != nil {
			return "", nil, err
		}
		fmt.Fprintln(os.Stderr, "no -w given; using embedded subdomain wordlist")
		return f, func() { os.Remove(f) }, nil
	}
	return "", nil, fmt.Errorf("wordlist required (-w)")
}

func init() {
	subdomainsCmd.Flags().StringVarP(&subWordlist, "wordlist", "w", "", "subdomain wordlist (defaults to embedded list)")
	subdomainsCmd.Flags().StringVar(&subNameserver, "nameserver", "", "DNS nameserver host:port for resolutions")
	rootCmd.AddCommand(subdomainsCmd)
}
