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
				t.Error("New() returned nil")
			}
			if c.client == nil {
				t.Error("New() client is nil")
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
