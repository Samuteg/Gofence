package cmd

import (
	"os"
	"path/filepath"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/spf13/cobra"
)

var (
	cfgFile   string
	noTUI     bool
	jsonOut   bool
	rateProf  string
	concur    int
	dbPath    string
)

var rootCmd = &cobra.Command{
	Use:   "gofence",
	Short: "Security testing CLI tool",
	Long:  "Gofence - Automated reconnaissance, vulnerability scanning and exploitation framework",
	RunE: func(cmd *cobra.Command, args []string) error {
		if isatty(os.Stdout) && !noTUI {
			return ux.RunTUI()
		}
		return cmd.Help()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(config.Init)

	home, _ := os.UserHomeDir()
	defaultDB := filepath.Join(home, ".gofence", "gofence.db")

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.gofence/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "force headless mode")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "force JSON output to stdout")
	rootCmd.PersistentFlags().StringVar(&rateProf, "rate", "normal", "rate limit profile: sneaky|normal|aggressive")
	rootCmd.PersistentFlags().IntVar(&concur, "concurrency", 100, "max concurrent goroutines")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", defaultDB, "sqlite database path")
}

func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
