package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/data"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var crawlDepth int

var crawlCmd = &cobra.Command{
	Use:   "crawl <url>",
	Short: "AST-based web crawler with secret detection",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL, err := stdinTarget(args)
		if err != nil {
			return err
		}
		client := httpclient.NewFromEnv()
		crawler := surface.NewCrawler(client, crawlDepth, concur)
		crawler.WAF = ux.NewWAFDetector(0)
		crawler.Limiter = ux.NewLimiter(ux.ProfileFromString(rateProf))

		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, hostOf(targetURL), "crawl"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}

		result := crawler.Crawl(targetURL)

		out, _ := json.MarshalIndent(result.URLs, "", "  ")
		fmt.Printf("URLs found (%d):\n%s\n", len(result.URLs), string(out))

		if len(result.Secrets) > 0 {
			secOut, _ := json.MarshalIndent(result.Secrets, "", "  ")
			fmt.Printf("Secrets found (%d):\n%s\n", len(result.Secrets), string(secOut))
		}

		if db != nil {
			host := hostOf(targetURL)
			ip := data.ResolveIP(host)
			for _, s := range result.Secrets {
				if err := db.SaveFinding(wsID, ip, host, secretSeverity(s.Type),
					fmt.Sprintf("secret %s", s.Type),
					fmt.Sprintf("source=%s snippet=%s", s.Source, s.Snippet)); err == nil {
					// persisted
				}
			}
			fmt.Fprintf(os.Stderr, "persisted %d secrets to workspace\n", len(result.Secrets))
			db.Close()
		}
		return nil
	},
}

func secretSeverity(t string) string {
	switch t {
	case "AWS_KEY", "AWS_SECRET", "JWT":
		return "high"
	default:
		return "medium"
	}
}

func init() {
	crawlCmd.Flags().IntVar(&crawlDepth, "depth", 3, "max crawl depth")
	rootCmd.AddCommand(crawlCmd)
}
