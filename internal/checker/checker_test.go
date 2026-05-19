package checker

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew tests the creation of a new Checker instance
func TestNew(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
	}{
		{
			name: "default options",
			opts: &Options{
				Timeout: 10,
				Workers: 5,
				Method:  "HEAD",
			},
		},
		{
			name: "with SSL disabled",
			opts: &Options{
				Timeout:    10,
				DisableSSL: true,
				Method:     "GET",
			},
		},
		{
			name: "with proxy",
			opts: &Options{
				Timeout:  10,
				ProxyURL: "http://localhost:8080",
				Method:   "HEAD",
			},
		},
		{
			name: "without follow redirects",
			opts: &Options{
				Timeout:         10,
				FollowRedirects: false,
				Method:          "HEAD",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.opts)
			if c == nil {
				t.Fatal("New() returned nil")
			}
			if c.client == nil {
				t.Fatal("New() client is nil")
			}
			if c.opts != tt.opts {
				t.Error("New() opts mismatch")
			}
		})
	}
}

// TestCheck tests the Check function with a mock server
func TestCheck(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		statusCode      int
		expectedSafe    int
		expectedUnsafe  int
		opts            *Options
		wantPresentCSP  bool
		wantPresentHSTS bool
	}{
		{
			name: "all security headers present",
			headers: map[string]string{
				"Strict-Transport-Security":    "max-age=31536000; includeSubDomains",
				"Content-Security-Policy":      "default-src 'self'",
				"X-Content-Type-Options":       "nosniff",
				"X-Frame-Options":              "DENY",
				"Referrer-Policy":              "strict-origin-when-cross-origin",
				"Permissions-Policy":           "geolocation=()",
				"Cross-Origin-Opener-Policy":   "same-origin",
				"Cross-Origin-Embedder-Policy": "require-corp",
				"Cross-Origin-Resource-Policy": "same-origin",
			},
			statusCode:      200,
			expectedSafe:    9,
			expectedUnsafe:  0,
			opts:            &Options{Timeout: 10, Method: "GET"},
			wantPresentCSP:  true,
			wantPresentHSTS: true,
		},
		{
			name:           "no security headers",
			headers:        map[string]string{},
			statusCode:     200,
			expectedSafe:   0,
			expectedUnsafe: 9, // All non-deprecated headers missing
			opts:           &Options{Timeout: 10, Method: "GET"},
		},
		{
			name: "partial headers",
			headers: map[string]string{
				"Strict-Transport-Security": "max-age=31536000",
				"X-Content-Type-Options":    "nosniff",
			},
			statusCode:      200,
			expectedSafe:    2,
			expectedUnsafe:  7,
			opts:            &Options{Timeout: 10, Method: "GET"},
			wantPresentHSTS: true,
		},
		{
			name: "CSP with frame-ancestors removes X-Frame-Options requirement",
			headers: map[string]string{
				"Content-Security-Policy": "frame-ancestors 'self'",
			},
			statusCode:     200,
			expectedSafe:   1,
			expectedUnsafe: 7, // X-Frame-Options not counted as missing
			opts:           &Options{Timeout: 10, Method: "GET"},
			wantPresentCSP: true,
		},
		{
			name: "X-XSS-Protection with value 0 should be warning",
			headers: map[string]string{
				"X-XSS-Protection": "0",
			},
			statusCode:     200,
			opts:           &Options{Timeout: 10, Method: "GET", ShowDeprecated: true},
			expectedSafe:   1,
			expectedUnsafe: 11, // Including deprecated
		},
		{
			name: "HSTS with max-age=0 should be error",
			headers: map[string]string{
				"Strict-Transport-Security": "max-age=0",
			},
			statusCode:     200,
			opts:           &Options{Timeout: 10, Method: "GET"},
			expectedSafe:   1,
			expectedUnsafe: 8,
		},
		{
			name: "show deprecated headers",
			headers: map[string]string{
				"X-XSS-Protection":                  "1; mode=block",
				"Expect-CT":                         "max-age=86400",
				"X-Permitted-Cross-Domain-Policies": "none",
			},
			statusCode:     200,
			opts:           &Options{Timeout: 10, Method: "GET", ShowDeprecated: true},
			expectedSafe:   3,
			expectedUnsafe: 9, // 12 total - 3 present
		},
		{
			name: "information disclosure headers",
			headers: map[string]string{
				"Server":       "Apache/2.4.41",
				"X-Powered-By": "PHP/7.4",
			},
			statusCode: 200,
			opts:       &Options{Timeout: 10, Method: "GET", ShowInfo: true},
		},
		{
			name: "cache headers",
			headers: map[string]string{
				"Cache-Control": "no-cache, no-store",
				"Pragma":        "no-cache",
				"ETag":          "abc123",
			},
			statusCode: 200,
			opts:       &Options{Timeout: 10, Method: "GET", ShowCache: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewTLSServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for k, v := range tt.headers {
						w.Header().Set(k, v)
					}
					w.WriteHeader(tt.statusCode)
				}),
			)
			defer server.Close()

			// Create checker with SSL disabled for test server
			opts := tt.opts
			opts.DisableSSL = true

			c := New(opts)
			result := c.Check(server.URL)

			// Basic checks
			if result == nil {
				t.Fatal("Check() returned nil")
			}

			if result.Error != "" {
				t.Errorf("Check() returned error: %s", result.Error)
			}

			if result.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", result.StatusCode, tt.statusCode)
			}

			// Check safe/unsafe counts if specified
			if tt.expectedSafe > 0 && result.SafeCount != tt.expectedSafe {
				t.Errorf("SafeCount = %d, want %d", result.SafeCount, tt.expectedSafe)
			}

			if tt.expectedUnsafe > 0 && result.UnsafeCount != tt.expectedUnsafe {
				t.Errorf("UnsafeCount = %d, want %d", result.UnsafeCount, tt.expectedUnsafe)
			}

			// Check specific headers presence
			if tt.wantPresentCSP {
				found := false
				for _, h := range result.PresentHeaders {
					if h.Name == "Content-Security-Policy" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected CSP in PresentHeaders")
				}
			}

			if tt.wantPresentHSTS {
				found := false
				for _, h := range result.PresentHeaders {
					if h.Name == "Strict-Transport-Security" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected HSTS in PresentHeaders")
				}
			}

			// Check info headers if requested
			if tt.opts.ShowInfo && len(tt.headers) > 0 {
				if _, ok := tt.headers["Server"]; ok {
					found := false
					for _, h := range result.InfoHeaders {
						if h.Name == "Server" {
							found = true
							break
						}
					}
					if !found {
						t.Error("Expected Server in InfoHeaders")
					}
				}
			}

			// Check cache headers if requested
			if tt.opts.ShowCache && len(tt.headers) > 0 {
				if _, ok := tt.headers["Cache-Control"]; ok {
					found := false
					for _, h := range result.CacheHeaders {
						if h.Name == "Cache-Control" {
							found = true
							break
						}
					}
					if !found {
						t.Error("Expected Cache-Control in CacheHeaders")
					}
				}
			}
		})
	}
}

// TestCheckAll tests concurrent checking of multiple targets
func TestCheckAll(t *testing.T) {
	// Create test servers
	server1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(200)
	}))
	defer server1.Close()

	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer server2.Close()

	opts := &Options{
		Timeout:    10,
		Workers:    2,
		Method:     "GET",
		DisableSSL: true,
	}

	c := New(opts)
	results := c.CheckAll([]string{server1.URL, server2.URL})

	if len(results) != 2 {
		t.Fatalf("CheckAll() returned %d results, want 2", len(results))
	}

	for i, result := range results {
		if result == nil {
			t.Errorf("Result %d is nil", i)
			continue
		}
		if result.Error != "" {
			t.Errorf("Result %d has error: %s", i, result.Error)
		}
	}
}

// TestCheckFallbackToGET tests the fallback from HEAD to GET on 404/405
func TestCheckFallbackToGET(t *testing.T) {
	headCalled := false
	getCalled := false

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			headCalled = true
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == "GET" {
			getCalled = true
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer server.Close()

	opts := &Options{
		Timeout:    10,
		Method:     "HEAD",
		DisableSSL: true,
	}

	c := New(opts)
	result := c.Check(server.URL)

	if !headCalled {
		t.Error("HEAD was not called")
	}
	if !getCalled {
		t.Error("GET fallback was not called")
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", result.StatusCode, http.StatusOK)
	}
}

// TestCheckWithError tests error handling
func TestCheckWithError(t *testing.T) {
	opts := &Options{
		Timeout: 1,
		Method:  "GET",
	}

	c := New(opts)

	// Test with invalid URL
	result := c.Check("http://invalid.invalid.invalid")
	if result.Error == "" {
		t.Error("Expected error for invalid host")
	}
}

// TestNormalizeURL tests URL normalization
func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"192.168.1.1", "http://192.168.1.1"},
		{"http://192.168.1.1", "http://192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeURL(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

// TestAppendPort tests port appending
func TestAppendPort(t *testing.T) {
	tests := []struct {
		target   string
		port     string
		expected string
	}{
		{"https://example.com", "8443", "https://example.com:8443"},
		{"http://example.com", "8080", "http://example.com:8080"},
		{"https://example.com:443", "8443", "https://example.com:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.target+":"+tt.port, func(t *testing.T) {
			result := appendPort(tt.target, tt.port)
			if result != tt.expected {
				t.Errorf(
					"appendPort(%s, %s) = %s, want %s",
					tt.target,
					tt.port,
					result,
					tt.expected,
				)
			}
		})
	}
}

// TestGetHeaderValue tests case-insensitive header retrieval
func TestGetHeaderValue(t *testing.T) {
	headers := http.Header{
		"Content-Type":              []string{"application/json"},
		"X-Custom-Header":           []string{"value1", "value2"},
		"Strict-Transport-Security": []string{"max-age=31536000"},
	}

	tests := []struct {
		name     string
		expected string
	}{
		{"Content-Type", "application/json"},
		{"content-type", "application/json"},
		{"CONTENT-TYPE", "application/json"},
		{"X-Custom-Header", "value1, value2"},
		{"strict-transport-security", "max-age=31536000"},
		{"Non-Existent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHeaderValue(headers, tt.name)
			if result != tt.expected {
				t.Errorf("getHeaderValue(%s) = %s, want %s", tt.name, result, tt.expected)
			}
		})
	}
}

// TestCheckWithCustomHeaders tests custom headers in request
func TestCheckWithCustomHeaders(t *testing.T) {
	receivedHeaders := make(map[string]string)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders["X-Custom"] = r.Header.Get("X-Custom")
		receivedHeaders["Authorization"] = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer server.Close()

	opts := &Options{
		Timeout:    10,
		Method:     "GET",
		DisableSSL: true,
		CustomHeaders: map[string]string{
			"X-Custom":      "test-value",
			"Authorization": "Bearer token123",
		},
	}

	c := New(opts)
	c.Check(server.URL)

	if receivedHeaders["X-Custom"] != "test-value" {
		t.Errorf("X-Custom header = %s, want test-value", receivedHeaders["X-Custom"])
	}
	if receivedHeaders["Authorization"] != "Bearer token123" {
		t.Errorf(
			"Authorization header = %s, want Bearer token123",
			receivedHeaders["Authorization"],
		)
	}
}

// TestCheckWithCookie tests cookie in request
func TestCheckWithCookie(t *testing.T) {
	var receivedCookie string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer server.Close()

	opts := &Options{
		Timeout:    10,
		Method:     "GET",
		DisableSSL: true,
		Cookie:     "session=abc123; token=xyz",
	}

	c := New(opts)
	c.Check(server.URL)

	if receivedCookie != "session=abc123; token=xyz" {
		t.Errorf("Cookie = %s, want session=abc123; token=xyz", receivedCookie)
	}
}

// TestAnalyzeCSP tests CSP analysis for security issues
func TestAnalyzeCSP(t *testing.T) {
	tests := []struct {
		name           string
		csp            string
		expectedIssues []string
		minIssues      int
	}{
		{
			name:      "secure CSP with all directives",
			csp:       "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
			minIssues: 0,
		},
		{
			name:           "CSP with unsafe-inline in script-src",
			csp:            "default-src 'self'; script-src 'self' 'unsafe-inline'",
			expectedIssues: []string{"script-src contains 'unsafe-inline'"},
			minIssues:      1,
		},
		{
			name:           "CSP with unsafe-eval in script-src",
			csp:            "default-src 'self'; script-src 'self' 'unsafe-eval'",
			expectedIssues: []string{"script-src contains 'unsafe-eval'"},
			minIssues:      1,
		},
		{
			name:           "CSP with data: in script-src",
			csp:            "script-src 'self' data:",
			expectedIssues: []string{"script-src contains data: URI scheme"},
			minIssues:      1,
		},
		{
			name:           "CSP with overly broad https: in script-src",
			csp:            "script-src https:",
			expectedIssues: []string{"script-src contains overly broad source 'https:'"},
			minIssues:      1,
		},
		{
			name:           "CSP with wildcard in script-src",
			csp:            "script-src *",
			expectedIssues: []string{"script-src contains overly broad source '*'"},
			minIssues:      1,
		},
		{
			name:           "CSP missing script-src and default-src",
			csp:            "frame-ancestors 'self'",
			expectedIssues: []string{"missing script-src directive"},
			minIssues:      1,
		},
		{
			name:      "CSP with only default-src (fallback)",
			csp:       "default-src 'self'; base-uri 'self'; form-action 'self'",
			minIssues: 0,
		},
		{
			name:           "CSP missing base-uri",
			csp:            "default-src 'self'; script-src 'self'",
			expectedIssues: []string{"missing base-uri directive"},
			minIssues:      1,
		},
		{
			name:           "CSP missing form-action",
			csp:            "default-src 'self'; base-uri 'self'",
			expectedIssues: []string{"missing form-action directive"},
			minIssues:      1,
		},
		{
			name:           "CSP with multiple issues",
			csp:            "script-src 'self' 'unsafe-inline' 'unsafe-eval' data:",
			expectedIssues: []string{"unsafe-inline", "unsafe-eval", "data:"},
			minIssues:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeCSP(tt.csp)

			if tt.minIssues > 0 && len(issues) < tt.minIssues {
				t.Errorf("analyzeCSP() returned %d issues, want at least %d. Issues: %v",
					len(issues), tt.minIssues, issues)
			}

			if tt.minIssues == 0 && len(issues) > 0 {
				t.Errorf("analyzeCSP() returned issues for secure CSP: %v", issues)
			}

			// Check for specific expected issues
			for _, expected := range tt.expectedIssues {
				found := false
				for _, issue := range issues {
					if contains(issue, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing '%s' not found in: %v", expected, issues)
				}
			}
		})
	}
}

// TestParseCSPDirectives tests CSP directive parsing
func TestParseCSPDirectives(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		expected map[string]string
	}{
		{
			name: "simple CSP",
			csp:  "default-src 'self'; script-src 'self' https://example.com",
			expected: map[string]string{
				"default-src": "'self'",
				"script-src":  "'self' https://example.com",
			},
		},
		{
			name: "CSP with upgrade-insecure-requests",
			csp:  "default-src 'self'; upgrade-insecure-requests",
			expected: map[string]string{
				"default-src":               "'self'",
				"upgrade-insecure-requests": "",
			},
		},
		{
			name: "CSP with extra whitespace",
			csp:  "  default-src   'self'  ;   script-src 'none'  ",
			expected: map[string]string{
				"default-src": "'self'",
				"script-src":  "'none'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			directives := parseCSPDirectives(tt.csp)

			for key, expectedValue := range tt.expected {
				if value, ok := directives[key]; !ok {
					t.Errorf("Missing directive '%s'", key)
				} else if key != "upgrade-insecure-requests" && value != expectedValue {
					// Skip value check for directives without values
					t.Errorf("Directive '%s' = '%s', want '%s'", key, value, expectedValue)
				}
			}
		})
	}
}

// TestCSPAnalysisInCheck tests that CSP analysis is integrated into Check
func TestCSPAnalysisInCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
		w.WriteHeader(200)
	}))
	defer server.Close()

	opts := &Options{
		Timeout:    10,
		Method:     "GET",
		DisableSSL: true,
	}

	c := New(opts)
	result := c.Check(server.URL)

	// Find CSP header in results
	var cspHeader *HeaderInfo
	for i := range result.PresentHeaders {
		if result.PresentHeaders[i].Name == "Content-Security-Policy" {
			cspHeader = &result.PresentHeaders[i]
			break
		}
	}

	if cspHeader == nil {
		t.Fatal("CSP header not found in results")
	}

	if cspHeader.Status != severityWarning {
		t.Errorf("CSP status = %s, want 'warning'", cspHeader.Status)
	}

	if len(cspHeader.Issues) == 0 {
		t.Error("CSP issues should not be empty for unsafe CSP")
	}

	// Check that unsafe-inline issue is reported
	found := false
	for _, issue := range cspHeader.Issues {
		if contains(issue, "unsafe-inline") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected unsafe-inline issue, got: %v", cspHeader.Issues)
	}
}

// TestAnalyzeReferrerPolicy tests Referrer-Policy analysis
func TestAnalyzeReferrerPolicy(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantIssues bool
		contains   string
	}{
		{"strict-origin-when-cross-origin is safe", "strict-origin-when-cross-origin", false, ""},
		{"no-referrer is safe", "no-referrer", false, ""},
		{"same-origin is safe", "same-origin", false, ""},
		{"strict-origin is safe", "strict-origin", false, ""},
		{"unsafe-url is unsafe", "unsafe-url", true, "leak"},
		{"origin is unsafe", "origin", true, "leak"},
		{"origin-when-cross-origin is unsafe", "origin-when-cross-origin", true, "leak"},
		{"no-referrer-when-downgrade is unsafe", "no-referrer-when-downgrade", true, "leak"},
		{"multiple values uses last", "origin, strict-origin-when-cross-origin", false, ""},
		{"invalid value", "invalid-policy", true, "unrecognized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeReferrerPolicy(tt.value)
			if tt.wantIssues && len(issues) == 0 {
				t.Error("Expected issues but got none")
			}
			if !tt.wantIssues && len(issues) > 0 {
				t.Errorf("Expected no issues but got: %v", issues)
			}
			if tt.contains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.contains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing '%s', got: %v", tt.contains, issues)
				}
			}
		})
	}
}

// TestAnalyzeHSTS tests HSTS analysis
func TestAnalyzeHSTS(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantIssues bool
		contains   string
	}{
		{"valid max-age 1 year", "max-age=31536000", false, ""},
		{"valid max-age 6 months", "max-age=15768000", false, ""},
		{"max-age=0 disables HSTS", "max-age=0", true, "disables"},
		{"max-age less than 6 months", "max-age=3600", true, "less than"},
		{"missing max-age", "includeSubDomains", true, "missing"},
		{
			"preload without includeSubDomains",
			"max-age=31536000; preload",
			true,
			"includeSubDomains",
		},
		{"valid with preload", "max-age=31536000; includeSubDomains; preload", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeHSTS(tt.value)
			if tt.wantIssues && len(issues) == 0 {
				t.Error("Expected issues but got none")
			}
			if !tt.wantIssues && len(issues) > 0 {
				t.Errorf("Expected no issues but got: %v", issues)
			}
			if tt.contains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.contains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing '%s', got: %v", tt.contains, issues)
				}
			}
		})
	}
}

// TestAnalyzeCORP tests Cross-Origin-Resource-Policy analysis
func TestAnalyzeCORP(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantIssues bool
	}{
		{"same-origin is valid", "same-origin", false},
		{"same-site is valid", "same-site", false},
		{"cross-origin warns", "cross-origin", true},
		{"invalid value", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeCORP(tt.value)
			if tt.wantIssues && len(issues) == 0 {
				t.Error("Expected issues but got none")
			}
			if !tt.wantIssues && len(issues) > 0 {
				t.Errorf("Expected no issues but got: %v", issues)
			}
		})
	}
}

// TestAnalyzeXFrameOptions tests X-Frame-Options analysis
func TestAnalyzeXFrameOptions(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantIssues bool
	}{
		{"DENY is valid", "DENY", false},
		{"deny lowercase is valid", "deny", false},
		{"SAMEORIGIN is valid", "SAMEORIGIN", false},
		{"ALLOW-FROM warns deprecated", "ALLOW-FROM https://example.com", true},
		{"invalid value", "INVALID", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeXFrameOptions(tt.value)
			if tt.wantIssues && len(issues) == 0 {
				t.Error("Expected issues but got none")
			}
			if !tt.wantIssues && len(issues) > 0 {
				t.Errorf("Expected no issues but got: %v", issues)
			}
		})
	}
}

// TestAnalyzeCookies tests cookie security analysis
func TestAnalyzeCookies(t *testing.T) {
	tests := []struct {
		name       string
		cookies    []*http.Cookie
		isHTTPS    bool
		hasHSTS    bool
		wantIssues bool
		issueCount int
	}{
		{
			name: "secure session cookie",
			cookies: []*http.Cookie{
				{Name: "session", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
			},
			isHTTPS:    true,
			hasHSTS:    true,
			wantIssues: false,
		},
		{
			name: "session cookie missing HttpOnly",
			cookies: []*http.Cookie{
				{Name: "session", Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode},
			},
			isHTTPS:    true,
			hasHSTS:    true,
			wantIssues: true,
		},
		{
			name: "cookie missing Secure on HTTPS",
			cookies: []*http.Cookie{
				{Name: "mycookie", Secure: false},
			},
			isHTTPS:    true,
			hasHSTS:    false,
			wantIssues: true,
		},
		{
			name: "cookie missing Secure but protected by HSTS",
			cookies: []*http.Cookie{
				{Name: "mycookie", Secure: false},
			},
			isHTTPS:    true,
			hasHSTS:    true,
			wantIssues: true, // Still an issue, but less severe
		},
		{
			name: "session cookie missing SameSite",
			cookies: []*http.Cookie{
				{Name: "sessionid", Secure: true, HttpOnly: true},
			},
			isHTTPS:    true,
			hasHSTS:    true,
			wantIssues: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzeCookies(tt.cookies, tt.isHTTPS, tt.hasHSTS)
			hasIssues := false
			for _, c := range result {
				if len(c.Issues) > 0 {
					hasIssues = true
					break
				}
			}
			if tt.wantIssues && !hasIssues {
				t.Error("Expected cookie issues but got none")
			}
			if !tt.wantIssues && hasIssues {
				t.Errorf("Expected no cookie issues but got some")
			}
		})
	}
}

// TestAnalyzeCORS tests CORS configuration analysis
func TestAnalyzeCORS(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantCORS   bool
		wantIssues bool
		contains   string
	}{
		{
			name:     "no CORS headers",
			headers:  http.Header{},
			wantCORS: false,
		},
		{
			name: "specific origin is safe",
			headers: http.Header{
				"Access-Control-Allow-Origin": []string{"https://example.com"},
			},
			wantCORS:   true,
			wantIssues: false,
		},
		{
			name: "wildcard origin warns",
			headers: http.Header{
				"Access-Control-Allow-Origin": []string{"*"},
			},
			wantCORS:   true,
			wantIssues: true,
			contains:   "public",
		},
		{
			name: "wildcard with credentials is critical",
			headers: http.Header{
				"Access-Control-Allow-Origin":      []string{"*"},
				"Access-Control-Allow-Credentials": []string{"true"},
			},
			wantCORS:   true,
			wantIssues: true,
			contains:   "CRITICAL",
		},
		{
			name: "null origin is dangerous",
			headers: http.Header{
				"Access-Control-Allow-Origin": []string{"null"},
			},
			wantCORS:   true,
			wantIssues: true,
			contains:   "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzeCORS(tt.headers)
			if tt.wantCORS && result == nil {
				t.Error("Expected CORS info but got nil")
				return
			}
			if !tt.wantCORS && result != nil {
				t.Error("Expected no CORS info but got some")
				return
			}
			if result == nil {
				return
			}
			if tt.wantIssues && len(result.Issues) == 0 {
				t.Error("Expected CORS issues but got none")
			}
			if !tt.wantIssues && len(result.Issues) > 0 {
				t.Errorf("Expected no CORS issues but got: %v", result.Issues)
			}
			if tt.contains != "" {
				found := false
				for _, issue := range result.Issues {
					if contains(issue, tt.contains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing '%s', got: %v", tt.contains, result.Issues)
				}
			}
		})
	}
}

// TestIsSessionCookie tests session cookie detection
func TestIsSessionCookie(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"session", true},
		{"PHPSESSID", true},
		{"JSESSIONID", true},
		{"auth_token", true},
		{"jwt_token", true},
		{"mycookie", false},
		{"preferences", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSessionCookie(tt.name)
			if result != tt.expected {
				t.Errorf("isSessionCookie(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// TestIsCSRFCookie tests CSRF cookie detection
func TestIsCSRFCookie(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"csrftoken", true},
		{"_csrf", true},
		{"xsrf-token", true},
		{"session", false},
		{"mycookie", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCSRFCookie(tt.name)
			if result != tt.expected {
				t.Errorf("isCSRFCookie(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
