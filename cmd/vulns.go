package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var vulnsTemplate string

var vulnsCmd = &cobra.Command{
	Use:   "vulns <alvo>",
	Short: "Run vulnerability templates against target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		client := httpclient.NewFromEnv()
		engine := surface.NewVulnEngine(client)

		var templates []*surface.VulnTemplate
		var err error

		info, err := os.Stat(vulnsTemplate)
		if err != nil {
			return fmt.Errorf("template path: %w", err)
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

		for _, tmpl := range templates {
			result := engine.RunTemplate(tmpl, target)
			if result.Matched {
				fmt.Printf("[MATCH] %s (%s): %s\n", result.Name, result.TemplateID, result.Details)
			}
		}
		return nil
	},
}

func init() {
	vulnsCmd.Flags().StringVarP(&vulnsTemplate, "template", "t", "", "template file or directory")
	rootCmd.AddCommand(vulnsCmd)
}
