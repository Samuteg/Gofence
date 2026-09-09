package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nixteg/gofence/internal/config"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/spf13/cobra"
)

// Version/commit são injetadas em tempo de build via ldflags:
//
//	go build -ldflags '-X github.com/nixteg/gofence/cmd.version=v1.0.0' -o gofence .
var (
	version = "dev"
	commit  = "none"
)

var (
	cfgFile       string
	noTUI         bool
	jsonOut       bool
	rateProf      string
	concur        int
	dbPath        string
	workspaceName string

	// cmdCtx é cancelado no SIGINT/SIGTERM: todos os comandos de rede
	// derivam dele para parar em cascata e liberar recursos (temp files,
	// estado de resume) via defer em vez de morrer no meio do scan.
	cmdCtx    context.Context
	cmdCancel context.CancelFunc
)

var rootCmd = &cobra.Command{
	Use:   "gofence",
	Short: "Security testing CLI tool",
	Long:  "Gofence - Automated reconnaissance, vulnerability scanning and exploitation framework",
	Version: fmt.Sprintf("%s (commit %s)", version, commit),
	RunE: func(cmd *cobra.Command, args []string) error {
		if ux.IsTTY(os.Stdout) && !noTUI {
			return ux.RunTUI()
		}
		return cmd.Help()
	},
}

// Execute é o ponto de entrada: normaliza shorthands multi-caractere
// estilo nmap (-iL/-oX) em flags longas antes do parse do pflag.
func Execute() error {
	rootCmd.SetArgs(normalizeNmapFlags(os.Args[1:]))
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(config.Init)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.gofence/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "force headless mode")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "force JSON output to stdout")
	rootCmd.PersistentFlags().StringVar(&rateProf, "rate", "", "rate limit profile: sneaky|normal|aggressive (default from config/env)")
	rootCmd.PersistentFlags().IntVar(&concur, "concurrency", 0, "max concurrent goroutines (default from config/env)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "sqlite database path (default from config/env)")
	rootCmd.PersistentFlags().StringVar(&workspaceName, "workspace", "", "active workspace name (overrides stored active workspace)")
}

// PersistentPreRun roda antes de todo comando: instala o handler de sinais
// e resolve a configuração efetiva (flag explícita > env/config > default).
func init() {
	orig := rootCmd.PersistentPreRunE
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		cmdCtx, cmdCancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		if orig != nil {
			return orig(cmd, args)
		}
		return nil
	}
	origPost := rootCmd.PersistentPostRunE
	rootCmd.PersistentPostRunE = func(cmd *cobra.Command, args []string) error {
		if cmdCancel != nil {
			cmdCancel()
		}
		if origPost != nil {
			return origPost(cmd, args)
		}
		return nil
	}
}

// Ctx retorna o contexto do comando atual (cancelado em SIGINT/SIGTERM).
func Ctx() context.Context {
	if cmdCtx == nil {
		return context.Background()
	}
	return cmdCtx
}

// effConcurrency resolve a concorrência efetiva: flag --concurrency >
// GOFENCE_CONCURRENCY/config.concurrency > default 100.
func effConcurrency() int {
	if concur > 0 {
		return concur
	}
	if c := config.Get().Concurrency; c > 0 {
		return c
	}
	return 100
}

// effRateProfile resolve o perfil de rate efetivo: flag --rate >
// GOFENCE_RATE_PROFILE/config.rate_profile > "normal".
func effRateProfile() string {
	if rateProf != "" {
		return rateProf
	}
	if r := config.Get().RateProfile; r != "" {
		return r
	}
	return "normal"
}

// effDBPath resolve o caminho do banco efetivo: flag --db >
// GOFENCE_DB_PATH/config.db_path > ~/.gofence/gofence.db.
func effDBPath() string {
	if dbPath != "" {
		return dbPath
	}
	if p := config.Get().DBPath; p != "" && p != "gofence.db" {
		return p
	}
	if p := config.Get().DBPath; p != "" {
		return p
	}
	return defaultDBPath()
}

// defaultDBPath retorna ~/.gofence/gofence.db com fallback seguro.
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "gofence.db"
	}
	return filepath.Join(home, ".gofence", "gofence.db")
}

func isatty(f *os.File) bool {
	return ux.IsTTY(f)
}
