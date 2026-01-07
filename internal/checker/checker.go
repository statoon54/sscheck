package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	severityWarning    = "warning"
	severityError      = "error"
	severityDeprecated = "deprecated"
)

// Options contains the configuration for the checker
type Options struct {
	CustomHeaders   map[string]string
	Port            string
	Cookie          string
	Method          string
	ProxyURL        string
	Timeout         int
	Workers         int
	DisableSSL      bool
	JSONOutput      bool
	ShowInfo        bool
	ShowCache       bool
	ShowDeprecated  bool
	ShowCookies     bool
	ShowCORS        bool
	ShowRedirection bool
	FollowRedirects bool
}

// Result contains the analysis result for a target
type Result struct {
	AllHeaders     http.Header      `json:"all_headers,omitempty"`
	Target         string           `json:"target"`
	EffectiveURL   string           `json:"effective_url"`
	Error          string           `json:"error,omitempty"`
	PresentHeaders []HeaderInfo     `json:"present_headers"`
	MissingHeaders []HeaderInfo     `json:"missing_headers"`
	InfoHeaders    []HeaderInfo     `json:"info_headers,omitempty"`
	CacheHeaders   []HeaderInfo     `json:"cache_headers,omitempty"`
	Cookies        []CookieInfo     `json:"cookies,omitempty"`
	CORS           *CORSInfo        `json:"cors,omitempty"`
	Redirection    *RedirectionInfo `json:"redirection,omitempty"`
	StatusCode     int              `json:"status_code"`
	SafeCount      int              `json:"safe_count"`
	UnsafeCount    int              `json:"unsafe_count"`
	Score          int              `json:"score"`
	Grade          string           `json:"grade"`
}

// Checker is the main security header checker
type Checker struct {
	client *http.Client
	opts   *Options
}

// New creates a new Checker instance
func New(opts *Options) *Checker {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   time.Duration(opts.Timeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(opts.Timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	if opts.DisableSSL {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		} // #nosec G402 -- User explicitly requested to disable SSL verification
	}

	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Checker{
		opts:   opts,
		client: client,
	}
}

// CheckAll checks multiple targets concurrently
func (c *Checker) CheckAll(targets []string) []*Result {
	results := make([]*Result, len(targets))
	var wg sync.WaitGroup

	// Set concurrency limit (acts as semaphore)
	workers := c.opts.Workers
	if workers <= 0 {
		workers = 10
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	// semaphore channel
	sem := make(chan struct{}, workers)

	// Process each target with controlled concurrency
	for i, target := range targets {
		wg.Go(func() {
			sem <- struct{}{} // Acquire semaphore
			defer func() { <-sem }()
			results[i] = c.Check(target)
		})
	}

	wg.Wait() // Wait for all goroutines to finish
	return results
}

// doRequestWithFallback makes an HTTP request with automatic fallback to GET if HEAD fails
func (c *Checker) doRequestWithFallback(target string) (*http.Response, error) {
	resp, err := c.doRequest(target, c.opts.Method)
	if err != nil {
		return nil, err
	}

	// If HEAD returns 404 or 405, retry with GET
	if c.opts.Method == "HEAD" &&
		(resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				fmt.Printf("Failed to close response body: %v\n", err)
			}
		}()
		return c.doRequest(target, "GET")
	}

	return resp, nil
}

// doRequest creates and executes an HTTP request with the specified method
func (c *Checker) doRequest(target, method string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set(
		"User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Set cookie if provided
	if c.opts.Cookie != "" {
		req.Header.Set("Cookie", c.opts.Cookie)
	}

	// Set custom headers
	for k, v := range c.opts.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	return resp, nil
}

// Check analyzes security headers for a single target
func (c *Checker) Check(target string) *Result {
	result := &Result{
		Target:         target,
		PresentHeaders: []HeaderInfo{},
		MissingHeaders: []HeaderInfo{},
		InfoHeaders:    []HeaderInfo{},
		CacheHeaders:   []HeaderInfo{},
	}

	// Normalize target URL
	target = normalizeURL(target)

	// Append custom port if specified
	if c.opts.Port != "" {
		target = appendPort(target, c.opts.Port)
	}

	// Make request with fallback to GET if HEAD fails
	resp, err := c.doRequestWithFallback(target)
	if err != nil {
		result.Error = fmt.Sprintf("Request failed: %v", err)
		return result
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}()

	result.EffectiveURL = resp.Request.URL.String()
	result.StatusCode = resp.StatusCode
	result.AllHeaders = resp.Header

	// Check if HTTPS
	isHTTPS := strings.HasPrefix(result.EffectiveURL, "https://")

	// Create a copy of security headers to work with
	secHeaders := make(map[string]string)
	maps.Copy(secHeaders, SecurityHeaders)

	// Check for CSP with frame-ancestors (makes X-Frame-Options unnecessary)
	cspValue := getHeaderValue(resp.Header, "Content-Security-Policy")
	if cspValue != "" && strings.Contains(strings.ToLower(cspValue), "frame-ancestors") {
		delete(secHeaders, "X-Frame-Options")
	}

	// Analyze security headers
	for header, severity := range secHeaders {
		value := getHeaderValue(resp.Header, header)
		if value != "" {
			result.SafeCount++
			info := HeaderInfo{
				Name:   header,
				Value:  value,
				Status: "ok",
			}

			// Check for problematic values
			switch strings.ToLower(header) {
			case "x-xss-protection":
				if value == "0" {
					info.Status = severityWarning
				}
			case "referrer-policy":
				issues := analyzeReferrerPolicy(value)
				if len(issues) > 0 {
					info.Status = severityWarning
					info.Issues = issues
				}
			case "strict-transport-security":
				issues := analyzeHSTS(value)
				if len(issues) > 0 {
					if hasHSTSError(issues) {
						info.Status = severityError
					} else {
						info.Status = severityWarning
					}
					info.Issues = issues
				}
			case "content-security-policy":
				issues := analyzeCSP(value)
				if len(issues) > 0 {
					info.Status = severityWarning
					info.Issues = issues
				}
			case "cross-origin-resource-policy":
				issues := analyzeCORP(value)
				if len(issues) > 0 {
					info.Status = severityWarning
					info.Issues = issues
				}
			case "x-content-type-options":
				if !strings.EqualFold(value, "nosniff") {
					info.Status = severityWarning
					info.Issues = []string{"invalid value, should be 'nosniff'"}
				}
			case "x-frame-options":
				issues := analyzeXFrameOptions(value)
				if len(issues) > 0 {
					info.Status = severityWarning
					info.Issues = issues
				}
			}

			result.PresentHeaders = append(result.PresentHeaders, info)
		} else {
			// Skip HSTS check for non-HTTPS
			if header == "Strict-Transport-Security" && !isHTTPS {
				continue
			}

			// Skip deprecated headers if not showing them
			if severity == "deprecated" && !c.opts.ShowDeprecated {
				continue
			}

			result.UnsafeCount++
			result.MissingHeaders = append(result.MissingHeaders, HeaderInfo{
				Name:     header,
				Severity: severity,
			})
		}
	}

	// Check information disclosure headers
	if c.opts.ShowInfo {
		for _, header := range InformationHeaders {
			value := getHeaderValue(resp.Header, header)
			if value != "" {
				result.InfoHeaders = append(result.InfoHeaders, HeaderInfo{
					Name:  header,
					Value: value,
				})
			}
		}
	}

	// Check cache headers
	if c.opts.ShowCache {
		for _, header := range CacheHeaders {
			value := getHeaderValue(resp.Header, header)
			if value != "" {
				result.CacheHeaders = append(result.CacheHeaders, HeaderInfo{
					Name:  header,
					Value: value,
				})
			}
		}
	}

	// Initialize Observatory score
	result.Score = 100 // Baseline

	// Analyze cookies
	if c.opts.ShowCookies {
		hasHSTS := getHeaderValue(resp.Header, "Strict-Transport-Security") != ""
		result.Cookies = analyzeCookies(resp.Cookies(), isHTTPS, hasHSTS)
	}

	// Analyze CORS
	if c.opts.ShowCORS {
		result.CORS = analyzeCORS(resp.Header)
	}

	// Apply final scoring adjustments based on collected data
	applyObservatoryScoring(result, isHTTPS)
	result.Grade = scoreToGrade(result.Score)

	return result
}

// normalizeURL ensures the target has a protocol
func normalizeURL(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// Try to detect if it's an IP address
		if net.ParseIP(target) != nil {
			return "http://" + target
		}
		// Default to https
		return "https://" + target
	}
	return target
}

// appendPort appends a custom port to the target URL
func appendPort(target, port string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	u.Host = u.Hostname() + ":" + port
	return u.String()
}

// getHeaderValue gets a header value case-insensitively
func getHeaderValue(headers http.Header, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.Join(v, ", ")
		}
	}
	return ""
}

// analyzeCSP analyzes a Content-Security-Policy header for security issues
func analyzeCSP(csp string) []string {
	var issues []string

	// Parse CSP directives
	directives := parseCSPDirectives(csp)

	// Check for missing critical directives
	hasDefaultSrc := false
	hasScriptSrc := false
	hasObjectSrc := false

	for directive := range directives {
		switch directive {
		case "default-src":
			hasDefaultSrc = true
		case "script-src":
			hasScriptSrc = true
		case "object-src":
			hasObjectSrc = true
		}
	}

	// script-src or default-src should be defined
	if !hasScriptSrc && !hasDefaultSrc {
		issues = append(issues, "missing script-src directive (no default-src fallback)")
	}

	// object-src should be defined and restricted
	if !hasObjectSrc && !hasDefaultSrc {
		issues = append(issues, "missing object-src directive (no default-src fallback)")
	}

	// Check script-src for unsafe values
	scriptSrc := directives["script-src"]
	if scriptSrc == "" {
		scriptSrc = directives["default-src"]
	}

	if scriptSrc != "" {
		scriptSrcLower := strings.ToLower(scriptSrc)

		// Check for unsafe-inline
		if strings.Contains(scriptSrcLower, "'unsafe-inline'") {
			issues = append(issues, "script-src contains 'unsafe-inline'")
		}

		// Check for unsafe-eval
		if strings.Contains(scriptSrcLower, "'unsafe-eval'") {
			issues = append(issues, "script-src contains 'unsafe-eval'")
		}

		// Check for data: URI
		if strings.Contains(scriptSrcLower, "data:") {
			issues = append(issues, "script-src contains data: URI scheme")
		}

		// Check for overly broad sources
		for _, broad := range CSPBroadSources {
			if strings.Contains(scriptSrcLower, broad) {
				issues = append(
					issues,
					fmt.Sprintf("script-src contains overly broad source '%s'", broad),
				)
				break
			}
		}
	}

	// Check object-src for unsafe values
	objectSrc := directives["object-src"]
	if objectSrc == "" {
		objectSrc = directives["default-src"]
	}

	if objectSrc != "" {
		objectSrcLower := strings.ToLower(objectSrc)

		// object-src should ideally be 'none'
		if objectSrcLower != "'none'" {
			// Check for overly broad sources
			for _, broad := range CSPBroadSources {
				if strings.Contains(objectSrcLower, broad) {
					issues = append(
						issues,
						fmt.Sprintf("object-src contains overly broad source '%s'", broad),
					)
					break
				}
			}
		}
	}

	// Check for base-uri not being restricted
	if _, hasBaseUri := directives["base-uri"]; !hasBaseUri {
		// Only warn if CSP is otherwise comprehensive
		if hasDefaultSrc || hasScriptSrc {
			issues = append(issues, "missing base-uri directive")
		}
	}

	// Check for form-action not being restricted
	if _, hasFormAction := directives["form-action"]; !hasFormAction {
		if hasDefaultSrc || hasScriptSrc {
			issues = append(issues, "missing form-action directive")
		}
	}

	// Note: upgrade-insecure-requests is recommended for HTTPS sites but not enforced

	return issues
}

// parseCSPDirectives parses a CSP header into a map of directive -> value
func parseCSPDirectives(csp string) map[string]string {
	directives := make(map[string]string)

	// Split by semicolon
	parts := strings.SplitSeq(csp, ";")
	for part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split directive name from values
		before, after, ok := strings.Cut(part, " ")
		if !ok {
			// Directive with no value (e.g., upgrade-insecure-requests)
			directives[strings.ToLower(part)] = ""
		} else {
			name := strings.ToLower(before)
			value := strings.TrimSpace(after)
			directives[name] = value
		}
	}

	return directives
}

// analyzeReferrerPolicy analyzes a Referrer-Policy header for security issues
func analyzeReferrerPolicy(value string) []string {
	var issues []string

	// Referrer-Policy can have multiple values separated by commas
	// The browser uses the last valid value
	policies := strings.Split(value, ",")
	lastPolicy := ""
	for _, p := range policies {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			lastPolicy = p
		}
	}

	if lastPolicy == "" {
		return issues
	}

	// Check for unsafe values
	if slices.Contains(ReferrerPolicyUnsafe, lastPolicy) {
		issues = append(
			issues,
			fmt.Sprintf("policy '%s' may leak sensitive URL information", lastPolicy),
		)
	}

	// Check if it's a valid known value
	allKnown := slices.Concat(ReferrerPolicyPrivate, ReferrerPolicyUnsafe)
	found := slices.Contains(allKnown, lastPolicy)
	if !found {
		issues = append(issues, fmt.Sprintf("unrecognized policy value '%s'", lastPolicy))
	}

	return issues
}

// analyzeHSTS analyzes a Strict-Transport-Security header for security issues
func analyzeHSTS(value string) []string {
	var issues []string
	valueLower := strings.ToLower(value)

	// Extract max-age value
	maxAgeRegex := regexp.MustCompile(`max-age=(\d+)`)
	matches := maxAgeRegex.FindStringSubmatch(valueLower)

	if len(matches) < 2 {
		issues = append(issues, "missing or invalid max-age directive")
		return issues
	}

	maxAge, err := strconv.Atoi(matches[1])
	if err != nil {
		issues = append(issues, "invalid max-age value")
		return issues
	}

	if maxAge == 0 {
		issues = append(issues, "max-age=0 disables HSTS")
	} else if maxAge < HSTSMinMaxAge {
		issues = append(issues, fmt.Sprintf("max-age=%d is less than recommended 6 months (%d seconds)", maxAge, HSTSMinMaxAge))
	}

	// Check for preload without includeSubDomains
	if strings.Contains(valueLower, "preload") &&
		!strings.Contains(valueLower, "includesubdomains") {
		issues = append(issues, "preload requires includeSubDomains")
	}

	return issues
}

// hasHSTSError checks if HSTS issues include critical errors
func hasHSTSError(issues []string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, "max-age=0") || strings.Contains(issue, "missing") ||
			strings.Contains(issue, "invalid") {
			return true
		}
	}
	return false
}

// analyzeCORP analyzes a Cross-Origin-Resource-Policy header
func analyzeCORP(value string) []string {
	var issues []string
	valueLower := strings.ToLower(strings.TrimSpace(value))

	validValues := []string{"same-origin", "same-site", "cross-origin"}
	found := slices.Contains(validValues, valueLower)

	if !found {
		issues = append(issues, fmt.Sprintf("unrecognized value '%s'", value))
	} else if valueLower == "cross-origin" {
		issues = append(issues, "cross-origin allows resources to be shared with any origin")
	}

	return issues
}

// analyzeXFrameOptions analyzes X-Frame-Options header
func analyzeXFrameOptions(value string) []string {
	var issues []string
	valueLower := strings.ToLower(strings.TrimSpace(value))

	if valueLower != "deny" && valueLower != "sameorigin" &&
		!strings.HasPrefix(valueLower, "allow-from") {
		issues = append(
			issues,
			fmt.Sprintf("unrecognized value '%s', should be DENY or SAMEORIGIN", value),
		)
	}

	if strings.HasPrefix(valueLower, "allow-from") {
		issues = append(issues, "ALLOW-FROM is deprecated and not supported by modern browsers")
	}

	return issues
}

// analyzeCookies analyzes cookies for security issues
func analyzeCookies(cookies []*http.Cookie, isHTTPS, hasHSTS bool) []CookieInfo {
	var result []CookieInfo

	for _, cookie := range cookies {
		info := CookieInfo{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSiteToString(cookie.SameSite),
			Path:     cookie.Path,
		}

		// Check for issues
		isSession := isSessionCookie(cookie.Name)
		isCSRF := isCSRFCookie(cookie.Name)

		// Secure flag checks
		if !cookie.Secure {
			if isHTTPS {
				if hasHSTS {
					info.Issues = append(info.Issues, "missing Secure flag (protected by HSTS)")
				} else {
					info.Issues = append(info.Issues, "missing Secure flag on HTTPS site")
				}
			} else {
				info.Issues = append(info.Issues, "missing Secure flag (site not using HTTPS)")
			}
		}

		// HttpOnly flag for session cookies
		if isSession && !cookie.HttpOnly {
			info.Issues = append(info.Issues, "session cookie missing HttpOnly flag")
		}

		// SameSite checks
		switch cookie.SameSite {
		case http.SameSiteDefaultMode, 0:
			if isSession {
				info.Issues = append(info.Issues, "session cookie missing SameSite attribute")
			}
			if isCSRF {
				info.Issues = append(info.Issues, "CSRF token cookie missing SameSite attribute")
			}
		case http.SameSiteNoneMode:
			if !cookie.Secure {
				info.Issues = append(info.Issues, "SameSite=None requires Secure flag")
			}
		}

		result = append(result, info)
	}

	return result
}

// sameSiteToString converts SameSite mode to string
func sameSiteToString(mode http.SameSite) string {
	switch mode {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// isSessionCookie checks if a cookie name suggests it's a session cookie
func isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range SessionCookieNames {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// isCSRFCookie checks if a cookie name suggests it's a CSRF token
func isCSRFCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range CSRFCookieNames {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// analyzeCORS analyzes CORS headers for security issues
func analyzeCORS(headers http.Header) *CORSInfo {
	allowOrigin := getHeaderValue(headers, "Access-Control-Allow-Origin")
	if allowOrigin == "" {
		return nil // CORS not implemented
	}

	info := &CORSInfo{
		AllowOrigin: allowOrigin,
		AllowCredentials: strings.EqualFold(
			getHeaderValue(headers, "Access-Control-Allow-Credentials"),
			"true",
		),
		AllowMethods: getHeaderValue(headers, "Access-Control-Allow-Methods"),
		AllowHeaders: getHeaderValue(headers, "Access-Control-Allow-Headers"),
	}

	// Check for dangerous configurations
	if allowOrigin == "*" {
		if info.AllowCredentials {
			info.Issues = append(
				info.Issues,
				"CRITICAL: Allow-Origin '*' with Allow-Credentials is a CSRF vulnerability",
			)
		} else {
			info.Issues = append(info.Issues, "public access via wildcard origin")
		}
	}

	if strings.EqualFold(allowOrigin, "null") {
		info.Issues = append(
			info.Issues,
			"allowing 'null' origin can be exploited via sandboxed iframes",
		)
	}

	return info
}
