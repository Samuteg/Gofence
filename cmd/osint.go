package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/recon"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var osintProvider string

var osintCmd = &cobra.Command{
	Use:   "osint <alvo>",
	Short: "Query OSINT APIs (Shodan, Censys, SecurityTrails)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, target, "osint"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if db == nil {
			// Sem workspace: segue sem persistência (o openWorkspace já avisou).
			db = nil
		}
		if db != nil {
			defer db.Close()
		}
		cfg := config.Get()
		client := httpclient.NewFromEnv()
		osintClient := recon.NewOSINTClient(client, cfg)

		results, err := osintClient.Query(target, osintProvider)
		if err != nil {
			return fmt.Errorf("osint query: %w", err)
		}

		if jsonOut {
			if err := ux.PrintJSON(results); err != nil {
				return err
			}
		} else {
			fmt.Print(osintClient.FormatOutput(results))
		}

		// Persiste os resultados OSINT como findings (best-effort).
		if db != nil {
			persisted := 0
			for _, r := range results {
				sev := "info"
				title := fmt.Sprintf("osint %s", r.Provider)
				details, _ := json.Marshal(r.Data)
				if err := db.SaveFinding(wsID, data.ResolveIP(target), target, sev,
					title, string(details)); err == nil {
					persisted++
				}
			}
			fmt.Fprintf(os.Stderr, "persisted %d osint findings to workspace\n", persisted)
		}
		return nil
	},
}

func init() {
	osintCmd.Flags().StringVar(&osintProvider, "provider", "all", "shodan|censys|securitytrails|all")
	rootCmd.AddCommand(osintCmd)
}
