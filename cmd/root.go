package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"sscheck/internal/checker"
	"sscheck/internal/ui"

	"github.com/gookit/color"
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
	proxyURL        string
	hostsFile       string
	timeout         int
	followRedirects bool
	interactive     bool
	workers         int
)

var rootCmd = &cobra.Command{
	Use:   "sscheck [targets...]",
	Short: "Security Headers Check - Analyze HTTP security headers",
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
	rootCmd.Flags().StringVar(&proxyURL, "proxy", "", "Set a proxy (e.g., http://127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&hostsFile, "hfile", "", "Load a list of hosts from a file")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.Flags().BoolVarP(&followRedirects, "follow", "f", true, "Follow redirects")
	rootCmd.Flags().
		BoolVarP(&interactive, "interactive", "i", false, "Run in interactive mode with TUI")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of concurrent workers")
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
	results := c.CheckAll(targets)

	if opts.JSONOutput {
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(output))
	} else {
		for _, result := range results {
			printResult(result, opts)
		}
	}
}

// Print result in human-readable format
func printResult(result *checker.Result, opts *checker.Options) {
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

	// Summary
	fmt.Println()
	fmt.Println("-------------------------------------------------------")
	fmt.Printf("[!] Analyzing headers for %s\n", color.Blue.Sprint(result.EffectiveURL))
	fmt.Printf("[+] %s security header(s) present\n", color.Green.Sprintf("%d", result.SafeCount))
	fmt.Printf("[-] %s security header(s) missing\n", color.Red.Sprintf("%d", result.UnsafeCount))
	fmt.Println()
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
