package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"sscheck/internal/checker"
	"sscheck/internal/ui"
	"sscheck/internal/version"

	"github.com/chelnak/ysmrr"
	"github.com/chelnak/ysmrr/pkg/animations"
	"github.com/chelnak/ysmrr/pkg/colors"
	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var (
	// Flags
	port            string
	cookie          string
	customHeaders   []string
	disableSSL      bool
	method          string
	jsonOutput      bool
	showInfo        bool
	showCache       bool
	showDeprecated  bool
	showCookies     bool
	showCORS        bool
	proxyURL        string
	hostsFile       string
	timeout         int
	followRedirects bool
	interactive     bool
	workers         int
	noSummary       bool
)

var rootCmd = &cobra.Command{
	Use:     "sscheck [targets...]",
	Short:   "Security Headers Check - Analyze HTTP security headers",
	Version: version.Short(),
	Long: `sscheck - Security Headers Check

A tool to analyze security headers on web servers.
Inspired by shcheck (https://github.com/santoru/shcheck)

Examples:
  sscheck https://example.com
  sscheck https://example.com https://google.com
  sscheck --hfile hosts.txt
  sscheck -i https://example.com  # Interactive mode with bubbletea UI

Author: Franck Paszkowski - Université de Lille - 2026
`,
	Run: checkMySecurityHeaders,
}

// Wrapper function to call the main check function
func checkMySecurityHeaders(cmd *cobra.Command, args []string) {
	targets := args

	// Load targets from file if provided
	if hostsFile != "" {
		fileTargets, err := loadTargetsFromFile(hostsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading hosts file: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	// Ensure at least one target is provided
	if len(targets) == 0 {
		err := cmd.Help()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error displaying help: %v\n", err)
		}
		os.Exit(1)
	}

	// Build options
	opts := checker.Options{
		Port:            port,
		Cookie:          cookie,
		CustomHeaders:   parseCustomHeaders(customHeaders),
		DisableSSL:      disableSSL,
		Method:          strings.ToUpper(method),
		JSONOutput:      jsonOutput,
		ShowInfo:        showInfo,
		ShowCache:       showCache,
		ShowDeprecated:  showDeprecated,
		ShowCookies:     showCookies,
		ShowCORS:        showCORS,
		ProxyURL:        proxyURL,
		Timeout:         timeout,
		FollowRedirects: followRedirects,
		Workers:         workers,
	}

	if interactive && !jsonOutput {
		// Interactive mode with bubbletea
		ui.RunInteractive(targets, &opts)
	} else {
		// CLI mode
		runCLI(targets, &opts)
	}
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&port, "port", "p", "", "Set a custom port to connect to")
	rootCmd.Flags().StringVarP(&cookie, "cookie", "c", "", "Set cookies for the request")
	rootCmd.Flags().
		StringArrayVarP(&customHeaders, "header", "H", nil, "Add custom headers (format: 'Header: value')")
	rootCmd.Flags().
		BoolVarP(&disableSSL, "disable-ssl", "d", false, "Disable SSL/TLS certificate validation")
	rootCmd.Flags().
		StringVarP(&method, "method", "m", "HEAD", "HTTP method to use (HEAD, GET, POST, PUT, DELETE)")
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")
	rootCmd.Flags().
		BoolVarP(&showInfo, "info", "I", false, "Display information disclosure headers")
	rootCmd.Flags().BoolVarP(&showCache, "cache", "x", false, "Display caching headers")
	rootCmd.Flags().
		BoolVarP(&showDeprecated, "deprecated", "k", false, "Display deprecated headers")
	rootCmd.Flags().
		BoolVar(&showCookies, "cookies", false, "Analyze cookies for security issues (use -m GET)")
	rootCmd.Flags().
		BoolVar(&showCORS, "cors", false, "Analyze CORS configuration (typically on APIs)")
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Set a proxy (e.g., http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&hostsFile, "hfile", "", "Load a list of hosts from a file")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.Flags().BoolVarP(&followRedirects, "follow", "f", true, "Follow redirects")
	rootCmd.Flags().
		BoolVarP(&interactive, "interactive", "i", false, "Run in interactive mode with TUI")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of concurrent workers")
	rootCmd.Flags().BoolVar(&noSummary, "no-summary", false, "Disable score summary table")
}

// Load targets from a file, one per line
func loadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file: %v\n", closeErr)
		}
	}()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return targets, nil
}

// Parse custom headers from command-line arguments
func parseCustomHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// Run the checker in CLI mode
func runCLI(targets []string, opts *checker.Options) {
	c := checker.New(opts)

	// Start spinner for non-JSON output
	var results []*checker.Result
	if opts.JSONOutput {
		results = c.CheckAll(targets)
	} else {
		results = runWithSpinner(c, targets)
	}

	if opts.JSONOutput {
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(output))
	} else {
		// Print detailed results
		for _, result := range results {
			printResult(result, opts, noSummary)
		}

		// Print score summary table if multiple targets
		if len(results) > 1 && !noSummary {
			printScoreSummary(results)
		}
	}
}

// runWithSpinner runs the check with a spinner animation using ysmrr
func runWithSpinner(c *checker.Checker, targets []string) []*checker.Result {
	// Create spinner manager
	sm := ysmrr.NewSpinnerManager(
		ysmrr.WithAnimation(animations.Dots),
		ysmrr.WithSpinnerColor(colors.FgHiBlue),
	)

	var successCount, errorCount atomic.Int32

	// Single progress spinner
	progressSpinner := sm.AddSpinner(fmt.Sprintf("Checking 0/%d targets...", len(targets)))
	sm.Start()

	results := c.CheckAllWithProgress(targets, func(completed, total int, result *checker.Result) {
		if result.Error != "" {
			errorCount.Add(1)
		} else {
			successCount.Add(1)
		}

		progressSpinner.UpdateMessage(
			fmt.Sprintf(
				"Checking %d/%d targets... (✓ %d | ✗ %d)",
				completed,
				total,
				successCount.Load(),
				errorCount.Load(),
			),
		)
	})

	progressSpinner.CompleteWithMessage(
		fmt.Sprintf(
			"Completed %d targets (✓ %d | ✗ %d)",
			len(targets),
			successCount.Load(),
			errorCount.Load(),
		),
	)
	sm.Stop()

	return results
}

// Print score summary table
func printScoreSummary(results []*checker.Result) {
	fmt.Println()
	color.Cyan.Println(" 📊 OBSERVATORY SCORE SUMMARY")
	fmt.Println()

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)

	// Configure header
	t.AppendHeader(table.Row{"Site", "Score", "Grade"})

	// Add rows
	for _, r := range results {
		if r.Error != "" {
			site := r.Target
			if len(site) > 50 {
				site = site[:47] + "..."
			}
			t.AppendRow(table.Row{
				site,
				color.Red.Sprint("ERROR"),
				"-",
			})
		} else {
			site := r.Target
			if len(site) > 50 {
				site = site[:47] + "..."
			}
			t.AppendRow(table.Row{
				site,
				getScoreColor(r.Score).Sprintf("%d", r.Score),
				getGradeColor(r.Grade).Sprint(r.Grade),
			})
		}
	}

	// Calculate average score
	totalScore := 0
	validCount := 0
	for _, r := range results {
		if r.Error == "" {
			totalScore += r.Score
			validCount++
		}
	}

	// Add separator and average row
	if validCount > 0 {
		avgScore := totalScore / validCount
		t.AppendSeparator()
		t.AppendRow(table.Row{
			color.Bold.Sprint("Average"),
			getScoreColor(avgScore).Sprintf("%d", avgScore),
			"-",
		})
	}

	// Render table
	t.Render()
	fmt.Println()

	// Print applied scoring rules for each site (if any results have rules)
	hasAnyRules := false
	for _, r := range results {
		if r.Error == "" && len(r.ScoreRules) > 0 {
			hasAnyRules = true
			break
		}
	}

	if hasAnyRules {
		color.Cyan.Println(" 📋 APPLIED SCORING RULES")
		fmt.Println()

		for _, r := range results {
			if r.Error != "" || len(r.ScoreRules) == 0 {
				continue
			}

			site := r.Target
			if len(site) > 60 {
				site = site[:57] + "..."
			}
			color.Bold.Printf(" %s (Score: %d)\n", site, r.Score)

			penalties := []checker.ScoreRule{}
			bonuses := []checker.ScoreRule{}
			bonusesNotApplied := []checker.ScoreRule{}

			for _, rule := range r.ScoreRules {
				if rule.Modifier < 0 {
					penalties = append(penalties, rule)
				} else if rule.Applied {
					bonuses = append(bonuses, rule)
				} else {
					bonusesNotApplied = append(bonusesNotApplied, rule)
				}
			}

			if len(penalties) > 0 {
				color.Red.Println("   Penalties:")
				for _, rule := range penalties {
					color.Gray.Printf("     • %s: %d\n", rule.Description, rule.Modifier)
				}
			}

			if len(bonuses) > 0 {
				color.Green.Println("   Bonuses:")
				for _, rule := range bonuses {
					color.Gray.Printf("     • %s: +%d\n", rule.Description, rule.Modifier)
				}
			}

			if len(bonusesNotApplied) > 0 {
				color.Yellow.Println("   Bonuses not applied (score < 90):")
				for _, rule := range bonusesNotApplied {
					color.Gray.Printf("     • %s: +%d\n", rule.Description, rule.Modifier)
				}
			}

			fmt.Println()
		}
	}
}

// Print result in human-readable format
func printResult(result *checker.Result, opts *checker.Options, noSummary bool) {
	fmt.Println()
	fmt.Println("=======================================================")
	fmt.Printf(" > sscheck - Security Headers Check\n")
	fmt.Println("-------------------------------------------------------")

	if result.Error != "" {
		color.Red.Printf("[!] Error checking %s: %s\n", result.Target, result.Error)
		return
	}

	fmt.Printf("[*] Analyzing headers of %s\n", color.Blue.Sprint(result.Target))
	fmt.Printf("[*] Effective URL: %s\n", color.Blue.Sprint(result.EffectiveURL))
	fmt.Println()

	// Present headers
	for _, h := range result.PresentHeaders {
		if h.Name == "Content-Security-Policy" {
			fmt.Printf("[*] Header %s is present!\n", color.Green.Sprint(h.Name))
			printCSP(h.Value)
			// Show CSP issues if any
			if len(h.Issues) > 0 {
				fmt.Println()
				color.Yellow.Println("[!] CSP Security Issues:")
				for _, issue := range h.Issues {
					color.Yellow.Printf("    ↳ %s\n", issue)
				}
			}
		} else {
			var headerColor color.Color
			switch h.Status {
			case "warning":
				headerColor = color.Yellow
			case "error":
				headerColor = color.Red
			default:
				headerColor = color.Green
			}
			fmt.Printf("[*] Header %s is present! (Value: %s)\n", headerColor.Sprint(h.Name), h.Value)
			// Show issues for other headers
			if len(h.Issues) > 0 {
				for _, issue := range h.Issues {
					color.Yellow.Printf("    ↳ %s\n", issue)
				}
			}
		}
	}

	// Missing headers
	for _, h := range result.MissingHeaders {
		var severityColor color.Color
		switch h.Severity {
		case "warning":
			severityColor = color.Yellow
		case "deprecated":
			if !opts.ShowDeprecated {
				continue
			}
			severityColor = color.Gray
		default:
			severityColor = color.Red
		}
		fmt.Printf("[!] Security header missing: %s\n", severityColor.Sprint(h.Name))
	}

	// Information disclosure headers
	if opts.ShowInfo && len(result.InfoHeaders) > 0 {
		fmt.Println()
		for _, h := range result.InfoHeaders {
			fmt.Printf(
				"[!] Possible information disclosure: %s (Value: %s)\n",
				color.Yellow.Sprint(h.Name),
				h.Value,
			)
		}
	}

	// Cache headers
	if opts.ShowCache && len(result.CacheHeaders) > 0 {
		fmt.Println()
		for _, h := range result.CacheHeaders {
			fmt.Printf(
				"[*] Cache control header %s is present! (Value: %s)\n",
				color.Blue.Sprint(h.Name),
				h.Value,
			)
		}
	}

	// Cookie analysis
	if opts.ShowCookies && len(result.Cookies) > 0 {
		fmt.Println()
		fmt.Println("[*] Cookie Security Analysis:")
		for _, c := range result.Cookies {
			flags := []string{}
			if c.Secure {
				flags = append(flags, color.Green.Sprint("Secure"))
			}
			if c.HttpOnly {
				flags = append(flags, color.Green.Sprint("HttpOnly"))
			}
			if c.SameSite != "" {
				flags = append(flags, color.Blue.Sprintf("SameSite=%s", c.SameSite))
			}
			flagStr := ""
			if len(flags) > 0 {
				flagStr = " [" + strings.Join(flags, ", ") + "]"
			}
			fmt.Printf("    Cookie: %s%s\n", color.Cyan.Sprint(c.Name), flagStr)
			for _, issue := range c.Issues {
				color.Yellow.Printf("      ↳ %s\n", issue)
			}
		}
	}

	// CORS analysis
	if opts.ShowCORS && result.CORS != nil {
		fmt.Println()
		fmt.Println("[*] CORS Configuration:")
		fmt.Printf(
			"    Access-Control-Allow-Origin: %s\n",
			color.Cyan.Sprint(result.CORS.AllowOrigin),
		)
		if result.CORS.AllowCredentials {
			fmt.Printf("    Access-Control-Allow-Credentials: %s\n", color.Yellow.Sprint("true"))
		}
		if result.CORS.AllowMethods != "" {
			fmt.Printf("    Access-Control-Allow-Methods: %s\n", result.CORS.AllowMethods)
		}
		for _, issue := range result.CORS.Issues {
			color.Red.Printf("    ↳ %s\n", issue)
		}
	}

	// Summary
	fmt.Println()
	fmt.Println("-------------------------------------------------------")
	fmt.Printf("[!] Analyzing headers for %s\n", color.Blue.Sprint(result.EffectiveURL))
	fmt.Printf("[+] %s security header(s) present\n", color.Green.Sprintf("%d", result.SafeCount))
	fmt.Printf("[-] %s security header(s) missing\n", color.Red.Sprintf("%d", result.UnsafeCount))
	fmt.Printf("📊 Observatory Score: %s | Grade: %s\n",
		getScoreColor(result.Score).Sprintf("%d", result.Score),
		getGradeColor(result.Grade).Sprint(result.Grade))
	fmt.Println()

	// Print applied scoring rules (unless noSummary is set)
	if !noSummary && len(result.ScoreRules) > 0 {
		fmt.Println()
		color.Cyan.Println(" 📋 APPLIED SCORING RULES")
		fmt.Println()

		penalties := []checker.ScoreRule{}
		bonuses := []checker.ScoreRule{}
		bonusesNotApplied := []checker.ScoreRule{}

		for _, rule := range result.ScoreRules {
			if rule.Modifier < 0 {
				penalties = append(penalties, rule)
			} else if rule.Applied {
				bonuses = append(bonuses, rule)
			} else {
				bonusesNotApplied = append(bonusesNotApplied, rule)
			}
		}

		if len(penalties) > 0 {
			color.Red.Println(" Penalties:")
			for _, rule := range penalties {
				color.Gray.Printf("   • %s: %d\n", rule.Description, rule.Modifier)
			}
			fmt.Println()
		}

		if len(bonuses) > 0 {
			color.Green.Println(" Bonuses:")
			for _, rule := range bonuses {
				color.Gray.Printf("   • %s: +%d\n", rule.Description, rule.Modifier)
			}
			fmt.Println()
		}

		if len(bonusesNotApplied) > 0 {
			color.Yellow.Println(" Bonuses not applied (score < 90):")
			for _, rule := range bonusesNotApplied {
				color.Gray.Printf("   • %s: +%d\n", rule.Description, rule.Modifier)
			}
			fmt.Println()
		}
	}
}

// Print Content-Security-Policy header with highlighted unsafe directives
func printCSP(csp string) {
	unsafeOperators := []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes", "wasm-unsafe-eval"}
	fmt.Println("Value:")
	directives := strings.Split(csp, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}
		parts := strings.SplitN(directive, " ", 2)
		name := parts[0]
		values := ""
		if len(parts) > 1 {
			values = parts[1]
			// Highlight wildcards
			values = strings.ReplaceAll(values, "*", color.Yellow.Sprint("*"))
			// Highlight unsafe operators
			for _, op := range unsafeOperators {
				values = strings.ReplaceAll(values, op, color.Red.Sprint(op))
			}
		}
		if values != "" {
			fmt.Printf("\t%s: %s\n", color.Blue.Sprint(name), values)
		} else {
			fmt.Printf("\t%s\n", color.Blue.Sprint(name))
		}
	}
}

// getScoreColor returns color based on score
func getScoreColor(score int) color.Color {
	switch {
	case score >= 90:
		return color.Green
	case score >= 70:
		return color.Yellow
	case score >= 50:
		return color.Magenta
	default:
		return color.Red
	}
}

// getGradeColor returns color based on grade
func getGradeColor(grade string) color.Color {
	switch grade[0] {
	case 'A':
		return color.Green
	case 'B':
		return color.Yellow
	case 'C':
		return color.Magenta
	default:
		return color.Red
	}
}
