package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nixteg/gofence/internal/surface"
	"github.com/spf13/cobra"
)

var tlsStrict bool

var tlsCmd = &cobra.Command{
	Use:   "tls <host:porta>",
	Short: "TLS certificate and cipher analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]
		if !strings.Contains(host, ":") {
			host = host + ":443"
		}

		info, err := surface.AnalyzeTLS(host, tlsStrict)
		if err != nil {
			return err
		}

		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	tlsCmd.Flags().BoolVar(&tlsStrict, "strict", false, "alert on TLS < 1.2")
	rootCmd.AddCommand(tlsCmd)
}
