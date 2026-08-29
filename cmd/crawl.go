package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var crawlDepth int

var crawlCmd = &cobra.Command{
	Use:   "crawl <url>",
	Short: "AST-based web crawler with secret detection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL := args[0]
		client := httpclient.NewFromEnv()
		crawler := surface.NewCrawler(client, crawlDepth, concur)

		result := crawler.Crawl(targetURL)

		out, _ := json.MarshalIndent(result.URLs, "", "  ")
		fmt.Printf("URLs found (%d):\n%s\n", len(result.URLs), string(out))

		if len(result.Secrets) > 0 {
			secOut, _ := json.MarshalIndent(result.Secrets, "", "  ")
			fmt.Printf("Secrets found (%d):\n%s\n", len(result.Secrets), string(secOut))
		}
		return nil
	},
}

func init() {
	crawlCmd.Flags().IntVar(&crawlDepth, "depth", 3, "max crawl depth")
	rootCmd.AddCommand(crawlCmd)
}
