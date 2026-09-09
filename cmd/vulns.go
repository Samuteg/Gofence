package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/assets"
	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var vulnsTemplate string

var vulnsCmd = &cobra.Command{
	Use:   "vulns <alvo>",
	Short: "Run vulnerability templates against target",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		client := httpclient.NewFromEnv()
		engine := surface.NewVulnEngine(client)

		var templates []*surface.VulnTemplate

		if vulnsTemplate == "" {
			templates, err = surface.LoadTemplateFS(assets.TemplatesFS())
			if err != nil {
				return fmt.Errorf("load embedded templates: %w", err)
			}
			fmt.Fprintln(os.Stderr, "no -t given; using embedded templates")
		} else {
			info, serr := os.Stat(vulnsTemplate)
			if serr != nil {
				return fmt.Errorf("template path: %w", serr)
			}
			if info.IsDir() {
				templates, err = surface.LoadTemplateDir(vulnsTemplate)
			} else {
				var t *surface.VulnTemplate
				t, err = surface.LoadTemplate(vulnsTemplate)
				templates = []*surface.VulnTemplate{t}
			}
			if err != nil {
				return fmt.Errorf("load template: %w", err)
			}
		}

		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, hostOf(target), "vulns"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		var (
			totalExec, totalMatched, totalFailed int
			persisted                            int
			matches                              []*surface.VulnResult
		)
		for _, tmpl := range templates {
			result := engine.RunTemplate(tmpl, target)
			totalExec += result.Executed
			totalFailed += result.Failed
			if result.Matched {
				totalMatched++
				matches = append(matches, result)
				fmt.Printf("[MATCH] %s (%s): %s\n", result.Name, result.TemplateID, result.Details)
			}
			if db != nil && result.Matched {
				host := hostOf(target)
				if err := db.SaveFinding(wsID, data.ResolveIP(host), host, "high",
					fmt.Sprintf("vuln %s", result.TemplateID), result.Details); err == nil {
					persisted++
				}
			}
		}

		if jsonOut {
			payload := map[string]interface{}{
				"target":   target,
				"matches":  matches,
				"summary": map[string]int{
					"templates": len(templates),
					"executed":  totalExec,
					"matched":   totalMatched,
					"failed":    totalFailed,
				},
			}
			if err := ux.PrintJSON(payload); err != nil {
				if db != nil {
					db.Close()
				}
				return err
			}
		} else {
			fmt.Printf("\nSUMMARY: templates=%d executed=%d matched=%d failed=%d\n",
				len(templates), totalExec, totalMatched, totalFailed)
		}

		if db != nil {
			fmt.Fprintf(os.Stderr, "persisted %d vuln findings to workspace\n", persisted)
			db.Close()
		}
		return nil
	},
}

func init() {
	vulnsCmd.Flags().StringVarP(&vulnsTemplate, "template", "t", "", "template file or directory (defaults to embedded templates)")
	rootCmd.AddCommand(vulnsCmd)
}
