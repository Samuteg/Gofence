package cmd

import (
	"fmt"

	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var (
	fuzzWordlist string
	fuzzHeader   string
	fuzzPost     string
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz <url>",
	Short: "Web fuzzer for paths, headers, and POST data",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL := args[0]
		if fuzzWordlist == "" {
			return fmt.Errorf("wordlist required (-w)")
		}

		client := httpclient.NewFromEnv()
		fuzzer := surface.NewFuzzer(client, concur)

		results, err := fuzzer.FuzzWeb(targetURL, fuzzWordlist, fuzzHeader, fuzzPost)
		if err != nil {
			return err
		}

		for r := range results {
			fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
		}
		return nil
	},
}

func init() {
	fuzzCmd.Flags().StringVarP(&fuzzWordlist, "wordlist", "w", "", "wordlist file path")
	fuzzCmd.Flags().StringVar(&fuzzHeader, "header", "", "header name for FUZZ (e.g. 'Host: FUZZ')")
	fuzzCmd.Flags().StringVar(&fuzzPost, "data", "", "POST data containing FUZZ")
	rootCmd.AddCommand(fuzzCmd)
}
