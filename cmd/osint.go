package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/recon"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var osintProvider string

var osintCmd = &cobra.Command{
	Use:   "osint <alvo>",
	Short: "Query OSINT APIs (Shodan, Censys, SecurityTrails)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cfg := config.Get()
		client := httpclient.NewFromEnv()
		osintClient := recon.NewOSINTClient(client, cfg)

		results, err := osintClient.Query(target, osintProvider)
		if err != nil {
			return fmt.Errorf("osint query: %w", err)
		}
		fmt.Print(osintClient.FormatOutput(results))
		return nil
	},
}

func init() {
	osintCmd.Flags().StringVar(&osintProvider, "provider", "all", "shodan|censys|securitytrails|all")
	rootCmd.AddCommand(osintCmd)
}
