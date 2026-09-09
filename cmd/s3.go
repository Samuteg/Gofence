package cmd

import (
	"fmt"
	"os"

	"github.com/nixteg/gofence/internal/assets"
	"github.com/nixteg/gofence/internal/surface"
	"github.com/nixteg/gofence/internal/ux"
	"github.com/nixteg/gofence/pkg/httpclient"
	"github.com/spf13/cobra"
)

var s3Cmd = &cobra.Command{
	Use:   "s3 <placeholder>",
	Short: "Enumerate S3 buckets from a wordlist (existence + visibility)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// O alvo é placeholder: os nomes testados vêm da wordlist.
		if _, err := stdinTarget(args); err != nil {
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

		db, wsID := openWorkspace()
		if db != nil {
			defer db.Close()
		}

		names := readWordlist(wordlist)
		persisted := 0
		var found []surface.S3Result
		for _, r := range fuzzer.FuzzS3(names) {
			if !r.Exists {
				continue
			}
			label := "exists"
			if r.Private {
				label = "exists/private"
			}
			fmt.Printf("[%d] %s (%s)\n", r.StatusCode, r.Bucket, label)
			found = append(found, r)
			if db != nil {
				details := fmt.Sprintf("bucket=%s status=%d visibility=%s url=%s", r.Bucket, r.StatusCode, label, r.URL)
				if err := db.SaveFinding(wsID, "", r.Bucket, "medium",
					"open s3 bucket", details); err == nil {
					persisted++
				}
			}
		}
		if db != nil {
			fmt.Fprintf(os.Stderr, "persisted %d s3 findings to workspace\n", persisted)
		}
		if jsonOut {
			if err := ux.PrintJSON(found); err != nil {
				return err
			}
		}
		return nil
	},
}

// resolveFuzzWordlist resolve a wordlist de buckets: -w explícita ou a
// wordlist de paths embutida como fallback (mesma política do fuzz).
// Retorna (path, cleanup, error).
func resolveFuzzWordlist() (string, func(), error) {
	if fuzzWordlist != "" {
		return fuzzWordlist, nil, nil
	}
	if assets.HasWordlist("paths.txt") {
		words, err := assets.Wordlist("paths.txt")
		if err != nil {
			return "", nil, err
		}
		f, err := writeTempWordlist(words, "s3")
		if err != nil {
			return "", nil, err
		}
		fmt.Fprintln(os.Stderr, "no -w given; using embedded wordlist")
		return f, func() { os.Remove(f) }, nil
	}
	return "", nil, fmt.Errorf("wordlist required (-w)")
}

func init() {
	s3Cmd.Flags().StringVarP(&fuzzWordlist, "wordlist", "w", "", "bucket-name wordlist (defaults to embedded list)")
	rootCmd.AddCommand(s3Cmd)
}
