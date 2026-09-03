package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nixteg/gofence/internal/assets"
	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var (
	fuzzWordlist   string
	fuzzHeader     string
	fuzzPost       string
	fuzzIgnore     []string
	fuzzWAFBackoff bool
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz <url>",
	Short: "Web fuzzer for paths, headers, and POST data",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL := args[0]
		if fuzzWordlist == "" {
			if assets.HasWordlist("paths.txt") {
				words, werr := assets.Wordlist("paths.txt")
				if werr != nil {
					return werr
				}
				f, err := writeTempWordlist(words, "paths")
				if err != nil {
					return err
				}
				defer os.Remove(f)
				fuzzWordlist = f
				fmt.Fprintln(os.Stderr, "no -w given; using embedded path wordlist")
			} else {
				return fmt.Errorf("wordlist required (-w)")
			}
		}

		client := httpclient.NewFromEnv()
		fuzzer := surface.NewFuzzer(client, concur)
		fuzzer.IgnoreStatus = parseStatuses(fuzzIgnore)
		fuzzer.Limiter = ux.NewLimiter(ux.ProfileFromString(rateProf))

		var waf *ux.WAFDetector
		if fuzzWAFBackoff {
			waf = ux.NewWAFDetector(0)
			fuzzer.WAF = waf
		}

		results, err := fuzzer.FuzzWeb(context.Background(), targetURL, fuzzWordlist, fuzzHeader, fuzzPost)
		if err != nil {
			return err
		}

		db, wsID := openWorkspace()
		var persisted int
		for r := range results {
			if r.WAF {
				continue
			}
			fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
			if db != nil {
				host := hostOf(targetURL)
				if err := db.SaveFinding(wsID, data.ResolveIP(host), host, "info",
					fmt.Sprintf("fuzz %d", r.StatusCode),
					fmt.Sprintf("url=%s size=%d", r.URL, r.Size)); err == nil {
					persisted++
				}
			}
		}
		if waf != nil && waf.Triggered() {
			fmt.Fprintf(os.Stderr, "WAF wall hit (%s): wave stopped. Re-run with --rate sneaky if needed.\n", waf.Signature())
		}
		if db != nil {
			fmt.Fprintf(os.Stderr, "persisted %d fuzz findings to workspace\n", persisted)
			db.Close()
		}
		return nil
	},
}

func init() {
	fuzzCmd.Flags().StringVarP(&fuzzWordlist, "wordlist", "w", "", "wordlist file path (defaults to embedded list)")
	fuzzCmd.Flags().StringVar(&fuzzHeader, "header", "", "header name for FUZZ (e.g. 'Host: FUZZ')")
	fuzzCmd.Flags().StringVar(&fuzzPost, "data", "", "POST data containing FUZZ")
	fuzzCmd.Flags().StringSliceVar(&fuzzIgnore, "ignore-status", nil, "suppress these status codes (e.g. 403,429)")
	fuzzCmd.Flags().BoolVar(&fuzzWAFBackoff, "waf-backoff", true, "stop the wave when a WAF checkpoint is detected")
	rootCmd.AddCommand(fuzzCmd)
}

func parseStatuses(in []string) []int {
	var out []int
	for _, s := range in {
		for _, p := range strings.Split(s, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
