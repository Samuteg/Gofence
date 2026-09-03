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
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := stdinTarget(args)
		if err != nil {
			return err
		}
		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, target, "brute"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if db != nil {
			db.Close()
		}
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteSSH(target, bruteUser, bruteWordlist) {
			fmt.Printf("[FOUND] ssh %s user=%s pass=%s\n", r.Target, r.Username, r.Password)
		}
		return nil
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
		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, target, "brute"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if db != nil {
			db.Close()
		}
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteHTTP(target, bruteUser, bruteWordlist) {
			fmt.Printf("[FOUND] http %s user=%s pass=%s\n", r.Target, r.Username, r.Password)
		}
		return nil
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
		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, target, "brute"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if db != nil {
			db.Close()
		}
		engine := exploit.NewBruteEngine(concur, bruteNoBackoff)
		for r := range engine.BruteFTP(target, bruteUser, bruteWordlist) {
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
