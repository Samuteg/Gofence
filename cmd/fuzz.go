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

	// fuzz-parity
	fuzzExcludeSize  []string
	fuzzStatusCodes  []string
	fuzzRecursive    bool
	fuzzDepth        int
	fuzzExtensions   []string
	fuzzVhost        bool
	fuzzRobots       bool
	fuzzSitemap      bool
	fuzzOutput       string
	fuzzResume       string
	fuzzAuth         string
	fuzzCookie       string
	fuzzUserAgent    string
	fuzzRetries      int
	fuzzProgress     bool

	// fuzz-advanced
	fuzzBearer    string
	fuzzNTLM      string
	fuzzParam     string
	fuzzS3        bool
	fuzzDNS       string
	fuzzNameserver string
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz <url>",
	Short: "Web fuzzer for paths, headers, and POST data",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL, err := stdinTarget(args)
		if err != nil {
			return err
		}
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
		fuzzer.StatusCodes = parseInts(fuzzStatusCodes)
		fuzzer.ExcludeSize = parseInt64s(fuzzExcludeSize)
		fuzzer.Retries = fuzzRetries
		fuzzer.Progress = fuzzProgress
		fuzzer.Limiter = ux.NewLimiter(ux.ProfileFromString(rateProf))

		if fuzzAuth != "" || fuzzBearer != "" || fuzzNTLM != "" {
			user, pass, _ := strings.Cut(fuzzAuth, ":")
			fuzzer.SetAuth(surface.FuzzAuth{User: user, Pass: pass, Cookie: fuzzCookie, UserAgent: fuzzUserAgent, Bearer: fuzzBearer, NTLM: fuzzNTLM})
		}
		if fuzzParam != "" {
			fuzzer.ParamFuzz = fuzzParam
		}

		var waf *ux.WAFDetector
		if fuzzWAFBackoff {
			waf = ux.NewWAFDetector(0)
			fuzzer.WAF = waf
		}

		db, wsID := openWorkspace()
		if err := requireScope(db, wsID, hostOf(targetURL), "fuzz"); err != nil {
			if db != nil {
				db.Close()
			}
			return err
		}

		// Modo s3: testa nomes de bucket (targetURL é só base/placeholder).
		if fuzzS3 {
			names := readWordlist(fuzzWordlist)
			for _, r := range fuzzer.FuzzS3(names) {
				if !r.Exists {
					continue
				}
				label := "exists"
				if r.Private {
					label = "exists/private"
				}
				fmt.Printf("[%d] %s (%s)\n", r.StatusCode, r.Bucket, label)
			}
			return nil
		}

		// Modo dns: resolve subdomínios via recon.Resolver.
		if fuzzDNS != "" {
			resolved, derr := surface.FuzzDNS(concur, fuzzDNS, fuzzWordlist, fuzzNameserver)
			if derr != nil {
				return derr
			}
			for _, r := range resolved {
				fmt.Printf("%s %s\n", r.Subdomain, r.IP)
			}
			return nil
		}

		// Fonte de paths: robots.txt/sitemap.xml viram wordlist temporária.
		if fuzzRobots || fuzzSitemap {
			var seeds []string
			if fuzzRobots {
				seeds = append(seeds, surface.RobotsPaths(client, targetURL)...)
			}
			if fuzzSitemap {
				seeds = append(seeds, surface.SitemapPaths(client, targetURL)...)
			}
			if len(seeds) > 0 {
				seedWL, serr := surface.SeedWordlist(seeds)
				if serr != nil {
					return serr
				}
				defer os.Remove(seedWL)
				fuzzWordlist = seedWL
				fmt.Fprintf(os.Stderr, "seeded wordlist from robots/sitemap (%d paths)\n", len(seeds))
			} else {
				fmt.Fprintln(os.Stderr, "robots/sitemap: no paths found; falling back to wordlist")
			}
		}

		// Resume: retoma sessão salva.
		if fuzzResume != "" {
			state, lerr := surface.LoadState(fuzzResume)
			if lerr != nil {
				return fmt.Errorf("resume: %w", lerr)
			}
			found, ferr := fuzzer.FuzzResume(context.Background(), *state)
			if ferr != nil {
				return ferr
			}
			for _, r := range found {
				fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
			}
			return nil
		}

		// Modo vhost dedicado.
		if fuzzVhost {
			found, verr := fuzzer.FuzzVhost(context.Background(), targetURL, fuzzWordlist)
			if verr != nil {
				return verr
			}
			for _, r := range found {
				fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
			}
			return nil
		}

		// Recursão BFS.
		if fuzzRecursive {
			all, rerr := fuzzer.FuzzRecursive(context.Background(), targetURL, fuzzWordlist, fuzzDepth)
			if rerr != nil {
				return rerr
			}
			for _, r := range all {
				fmt.Printf("[%d] %s (size: %d, depth: %d)\n", r.StatusCode, r.URL, r.Size, r.Depth)
			}
			return nil
		}

		// Extensões automáticas (-x).
		effectiveWL := fuzzWordlist
		if len(fuzzExtensions) > 0 {
			extWL, xerr := fuzzer.ExtendWordlist(fuzzWordlist, fuzzExtensions)
			if xerr != nil {
				return xerr
			}
			defer os.Remove(extWL)
			effectiveWL = extWL
		}

		results, err := fuzzer.FuzzWeb(context.Background(), targetURL, effectiveWL, fuzzHeader, fuzzPost)
		if err != nil {
			db.Close()
			return err
		}

		var persisted int
		var findings []surface.FuzzResult
		for r := range results {
			if r.WAF || r.Wildcard {
				continue
			}
			fmt.Printf("[%d] %s (size: %d)\n", r.StatusCode, r.URL, r.Size)
			findings = append(findings, r)
			if db != nil {
				host := hostOf(targetURL)
				if err := db.SaveFinding(wsID, data.ResolveIP(host), host, "info",
					fmt.Sprintf("fuzz %d", r.StatusCode),
					fmt.Sprintf("url=%s size=%d", r.URL, r.Size)); err == nil {
					persisted++
				}
			}
		}

		// -o: grava estado para resume.
		if fuzzOutput != "" {
			state := surface.FuzzState{
				TargetURL: targetURL,
				Wordlist:  effectiveWL,
				Findings:  findings,
				Done:      true,
			}
			if serr := fuzzer.SaveState(fuzzOutput, state); serr != nil {
				fmt.Fprintf(os.Stderr, "warn: save state: %v\n", serr)
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

func parseInts(in []string) []int {
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

func parseInt64s(in []string) []int64 {
	var out []int64
	for _, s := range in {
		for _, p := range strings.Split(s, ",") {
			if n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func init() {
	fuzzCmd.Flags().StringVarP(&fuzzWordlist, "wordlist", "w", "", "wordlist file path (defaults to embedded list)")
	fuzzCmd.Flags().StringVar(&fuzzHeader, "header", "", "header name for FUZZ (e.g. 'Host: FUZZ')")
	fuzzCmd.Flags().StringVar(&fuzzPost, "data", "", "POST data containing FUZZ")
	fuzzCmd.Flags().StringSliceVar(&fuzzIgnore, "ignore-status", nil, "suppress these status codes (e.g. 403,429)")
	fuzzCmd.Flags().BoolVar(&fuzzWAFBackoff, "waf-backoff", true, "stop the wave when a WAF checkpoint is detected")

	fuzzCmd.Flags().StringSliceVar(&fuzzExcludeSize, "exclude-length", nil, "suppress responses with these body sizes")
	fuzzCmd.Flags().StringSliceVar(&fuzzStatusCodes, "status-codes", nil, "show only these status codes (e.g. 200,301)")
	fuzzCmd.Flags().BoolVar(&fuzzRecursive, "recursive", false, "re-fuzz discovered directories (BFS)")
	fuzzCmd.Flags().IntVar(&fuzzDepth, "depth", 3, "max recursion depth (with --recursive)")
	fuzzCmd.Flags().StringSliceVar(&fuzzExtensions, "x", nil, "append extensions to each word (e.g. php,html)")
	fuzzCmd.Flags().BoolVar(&fuzzVhost, "vhost", false, "fuzz vhosts via Host header, filtering base responses")
	fuzzCmd.Flags().BoolVar(&fuzzRobots, "robots", false, "seed wordlist from robots.txt")
	fuzzCmd.Flags().BoolVar(&fuzzSitemap, "sitemap", false, "seed wordlist from sitemap.xml")
	fuzzCmd.Flags().StringVarP(&fuzzOutput, "output", "o", "", "save progress state to file (resumable)")
	fuzzCmd.Flags().StringVar(&fuzzResume, "resume", "", "resume fuzz session from saved state")
	fuzzCmd.Flags().StringVar(&fuzzAuth, "auth", "", "basic auth user:pass")
	fuzzCmd.Flags().StringVar(&fuzzCookie, "cookie", "", "Cookie header value")
	fuzzCmd.Flags().StringVar(&fuzzUserAgent, "user-agent", "", "custom User-Agent")
	fuzzCmd.Flags().IntVar(&fuzzRetries, "retries", 2, "extra attempts per word on transport errors")
	fuzzCmd.Flags().BoolVar(&fuzzProgress, "progress", true, "show progress on stderr")
	fuzzCmd.Flags().StringVar(&fuzzBearer, "bearer", "", "Bearer token for Authorization header")
	fuzzCmd.Flags().StringVar(&fuzzNTLM, "ntlm", "", "NTLM credentials user:pass (HTTP NTLMv2)")
	fuzzCmd.Flags().StringVar(&fuzzParam, "param", "", "fuzz this query parameter with each word (e.g. user)")
	fuzzCmd.Flags().BoolVar(&fuzzS3, "s3", false, "test bucket names from wordlist against S3")
	fuzzCmd.Flags().StringVar(&fuzzDNS, "dns", "", "fuzz subdomains of this domain (gobuster dns style)")
	fuzzCmd.Flags().StringVar(&fuzzNameserver, "nameserver", "", "DNS nameserver host:port for --dns mode")
	rootCmd.AddCommand(fuzzCmd)
}

func readWordlist(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
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