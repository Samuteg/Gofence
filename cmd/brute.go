package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/exploit"
	"github.com/spf13/cobra"
)

var (
	bruteUser      string
	bruteWordlist  string
	bruteNoBackoff bool
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Brute force SSH/FTP/HTTP services",
}

// runBrute executa o brute force de um serviço, persistindo credenciais
// encontradas como findings no workspace (severity high). Fatorado pois os
// três subcomandos diferem apenas na função do engine.
func runBrute(service, target string, brute func() <-chan exploit.BruteResult) error {
	db, wsID := openWorkspace()
	if err := requireScope(db, wsID, target, "brute"); err != nil {
		if db != nil {
			db.Close()
		}
		return err
	}
	if db != nil {
		defer db.Close()
	}

	persisted := 0
	for r := range brute() {
		fmt.Printf("[FOUND] %s %s user=%s pass=%s\n", service, r.Target, r.Username, r.Password)
		if db != nil {
			details := fmt.Sprintf("service=%s user=%s", service, r.Username)
			if err := db.SaveFinding(wsID, data.ResolveIP(target), target, "high",
				fmt.Sprintf("brute %s credential", service), details); err == nil {
				persisted++
			}
		}
	}
	if db != nil {
		fmt.Fprintf(os.Stderr, "persisted %d brute findings to workspace\n", persisted)
	}
	return nil
}

var bruteSSH = &cobra.Command{
	Use:   "ssh <alvo>",
	Short: "SSH dictionary attack",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		return runBrute("ssh", target, func() <-chan exploit.BruteResult {
			engine := exploit.NewBruteEngine(effConcurrency(), bruteNoBackoff)
			return engine.BruteSSHContext(Ctx(), target, bruteUser, bruteWordlist)
		})
	},
}

var bruteHTTP = &cobra.Command{
	Use:   "http <url>",
	Short: "HTTP Basic auth brute force",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		return runBrute("http", target, func() <-chan exploit.BruteResult {
			engine := exploit.NewBruteEngine(effConcurrency(), bruteNoBackoff)
			return engine.BruteHTTPContext(Ctx(), target, bruteUser, bruteWordlist)
		})
	},
}

var bruteFTP = &cobra.Command{
	Use:   "ftp <alvo>",
	Short: "FTP dictionary attack",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		return runBrute("ftp", target, func() <-chan exploit.BruteResult {
			engine := exploit.NewBruteEngine(effConcurrency(), bruteNoBackoff)
			return engine.BruteFTPContext(Ctx(), target, bruteUser, bruteWordlist)
		})
	},
}

func init() {
	for _, c := range []*cobra.Command{bruteSSH, bruteHTTP, bruteFTP} {
		c.Flags().StringVarP(&bruteUser, "user", "u", "", "username")
		c.Flags().StringVarP(&bruteWordlist, "wordlist", "w", "", "password wordlist")
		c.Flags().BoolVar(&bruteNoBackoff, "no-backoff", false, "disable lockout protection")
		bruteCmd.AddCommand(c)
	}
	rootCmd.AddCommand(bruteCmd)
}
