package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/spf13/cobra"
)

var tlsStrict bool

var tlsCmd = &cobra.Command{
	Use:   "tls <host:porta>",
	Short: "TLS certificate and cipher analysis",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := stdinTarget(args)
		if err != nil {
			return err
		}
		if !strings.Contains(host, ":") {
			host = host + ":443"
		}

		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, host, "tls"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}

		info, err := surface.AnalyzeTLS(host, tlsStrict)
		if err != nil {
			db.Close()
			return err
		}

		out, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(out))

		if db != nil {
			hostname := strings.Split(host, ":")[0]
			sev := "info"
			if info.Grade == "C" {
				sev = "medium"
			}
			infoJSON, _ := json.Marshal(info)
			if err := db.SaveFinding(wsID, data.ResolveIP(hostname), hostname, sev,
				fmt.Sprintf("tls grade %s", info.Grade), string(infoJSON)); err == nil {
				fmt.Fprintln(os.Stderr, "persisted tls finding to workspace")
			}
			db.Close()
		}
		return nil
	},
}

func init() {
	tlsCmd.Flags().BoolVar(&tlsStrict, "strict", false, "probe for legacy protocols and warn on TLS < 1.2")
	rootCmd.AddCommand(tlsCmd)
}
