package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
	FollowRedirects bool
}

// Result contains the analysis result for a target
type Result struct {
	AllHeaders     http.Header  `json:"all_headers,omitempty"`
	Target         string       `json:"target"`
	EffectiveURL   string       `json:"effective_url"`
	Error          string       `json:"error,omitempty"`
	PresentHeaders []HeaderInfo `json:"present_headers"`
	MissingHeaders []HeaderInfo `json:"missing_headers"`
	InfoHeaders    []HeaderInfo `json:"info_headers,omitempty"`
	CacheHeaders   []HeaderInfo `json:"cache_headers,omitempty"`
	StatusCode     int          `json:"status_code"`
	SafeCount      int          `json:"safe_count"`
	UnsafeCount    int          `json:"unsafe_count"`
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

	// Create worker pool
	workers := c.opts.Workers
	if workers <= 0 {
		workers = 10
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	jobs := make(chan int, len(targets))

	// Start workers
	for range workers {
		wg.Go(func() {
			for idx := range jobs {
				results[idx] = c.Check(targets[idx])
			}
		})
	}

	// Send jobs
	for i := range targets {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	return results
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

	// Create request
	req, err := http.NewRequestWithContext(context.Background(), c.opts.Method, target, http.NoBody)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
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

	// Make request
	resp, err := c.client.Do(req)
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
	for k, v := range SecurityHeaders {
		secHeaders[k] = v
	}

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
					info.Status = "warning"
				}
			case "referrer-policy":
				if value == "unsafe-url" {
					info.Status = "error"
				}
			case "strict-transport-security":
				if strings.Contains(value, "max-age=0") {
					info.Status = "error"
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
