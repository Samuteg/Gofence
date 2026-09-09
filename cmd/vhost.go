package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var vhostCmd = &cobra.Command{
	Use:   "vhost <url>",
	Short: "Discover virtual hosts by fuzzing the Host header",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL, err := stdinTarget(args)
		if err != nil {
			return err
		}
		wordlist, cleanup, err := resolveFuzzWordlist()
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}

		client := httpclient.NewFromEnv()
		fuzzer := surface.NewFuzzer(client, effConcurrency())
		fuzzer.Limiter = ux.NewLimiter(ux.ProfileFromString(effRateProfile()))

		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, hostOf(targetURL), "vhost"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}
		if db != nil {
			defer db.Close()
		}

		found, err := fuzzer.FuzzVhost(Ctx(), targetURL, wordlist)
		if err != nil {
			return err
		}
		persisted := 0
		for _, r := range found {
			fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
			if db != nil {
				host := hostOf(targetURL)
				if err := db.SaveFinding(wsID, data.ResolveIP(host), host, "info",
					fmt.Sprintf("vhost %d", r.StatusCode),
					fmt.Sprintf("url=%s size=%d", r.URL, r.Size)); err == nil {
					persisted++
				}
			}
		}
		if db != nil {
			fmt.Fprintf(os.Stderr, "persisted %d vhost findings to workspace\n", persisted)
		}
		if jsonOut {
			if err := ux.PrintJSON(found); err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	vhostCmd.Flags().StringVarP(&fuzzWordlist, "wordlist", "w", "", "vhost-name wordlist (defaults to embedded list)")
	rootCmd.AddCommand(vhostCmd)
}
