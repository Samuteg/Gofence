package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nixteg/gofence/internal/data"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOut    string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Aggregate findings from the database into a Markdown/JSON report",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := data.New(dbPath)
		if err != nil {
			return err
		}
		defer db.Close()

		wsID, err := db.ActiveWorkspace(workspaceName)
		if err != nil {
			return err
		}

		hosts, err := db.Hosts(wsID)
		if err != nil {
			return err
		}
		findings, err := db.Findings(wsID)
		if err != nil {
			return err
		}

		var b strings.Builder
		b.WriteString(fmt.Sprintf("# Gofence report\n\n"))
		b.WriteString(fmt.Sprintf("Workspace id=%d\n\n", wsID))

		b.WriteString("## Hosts\n\n")
		for _, h := range hosts {
			b.WriteString(fmt.Sprintf("### %s (%s)\n", h.Hostname, h.IP))
			ports, _ := db.Ports(h.ID)
			if len(ports) > 0 {
				b.WriteString("| port | service | state |\n|---|---|---|\n")
				for _, p := range ports {
					b.WriteString(fmt.Sprintf("| %d | %s | %s |\n", p.Port, p.Service, p.State))
				}
			} else {
				b.WriteString("_no ports_\n")
			}
			b.WriteString("\n")
		}

		b.WriteString("## Findings\n\n")
		if len(findings) == 0 {
			b.WriteString("_no findings_\n")
		} else {
			b.WriteString("| severity | title | data |\n|---|---|---|\n")
			for _, f := range findings {
				b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Severity, f.Title, strings.ReplaceAll(f.Data, "\n", " ")))
			}
		}

		out := b.String()
		if reportFormat == "json" {
			payload := map[string]interface{}{
				"workspace_id": wsID,
				"hosts":        hosts,
				"findings":     findings,
			}
			if j, err := json.MarshalIndent(payload, "", "  "); err == nil {
				out = string(j) + "\n"
			}
		}

		if reportOut != "" {
			return os.WriteFile(reportOut, []byte(out), 0644)
		}
		fmt.Print(out)
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "md", "report format: md|json")
	reportCmd.Flags().StringVar(&reportOut, "out", "", "write report to file instead of stdout")
	rootCmd.AddCommand(reportCmd)
}
