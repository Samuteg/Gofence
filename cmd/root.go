package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gofence",
	Short: "Security testing CLI tool",
	Long:  "Gofence - Automated reconnaissance, vulnerability scanning and exploitation framework",
}

func Execute() error {
	return rootCmd.Execute()
}
