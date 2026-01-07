package checker

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestScoreToGrade tests the score to grade conversion
func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		name  string
		score int
		want  string
	}{
		{"A+ grade max", 145, "A+"},
		{"A+ grade min", 100, "A+"},
		{"A grade", 95, "A"},
		{"A grade min", 90, "A"},
		{"A- grade", 85, "A-"},
		{"B+ grade", 80, "B+"},
		{"B grade", 75, "B"},
		{"B grade min", 70, "B"},
		{"B- grade", 65, "B-"},
		{"C+ grade", 60, "C+"},
		{"C grade", 55, "C"},
		{"C grade min", 50, "C"},
		{"C- grade", 45, "C-"},
		{"D+ grade", 40, "D+"},
		{"D grade", 35, "D"},
		{"D grade min", 30, "D"},
		{"D- grade", 25, "D-"},
		{"F grade", 24, "F"},
		{"F grade zero", 0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreToGrade(tt.score)
			if got != tt.want {
				t.Errorf("scoreToGrade(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

// TestApplyScorePenalty tests the score penalty application
func TestApplyScorePenalty(t *testing.T) {
	tests := []struct {
		name          string
		initialScore  int
		rule          string
		expectedScore int
	}{
		{"CSP missing", 100, "csp-missing", 75},
		{"CSP unsafe-inline", 100, "csp-unsafe-inline", 80},
		{"CSP unsafe-eval", 100, "csp-unsafe-eval", 90},
		{"Cookies secure all (bonus)", 100, "cookies-secure-all", 105},
		{"Cookies session no secure", 100, "cookies-session-no-secure", 60},
		{"Cookies session no httponly", 100, "cookies-session-no-httponly", 70},
		{"Cookies no secure", 100, "cookies-no-secure", 80},
		{"Cookies no secure with HSTS", 100, "cookies-no-secure-hsts", 95},
		{"CORS wildcard critical", 100, "cors-wildcard-critical", 50},
		{"Referrer private (bonus)", 100, "referrer-private", 105},
		{"Referrer unsafe", 100, "referrer-unsafe", 95},
		{"HSTS missing", 100, "hsts-missing", 80},
		{"HSTS short", 100, "hsts-short", 90},
		{"HSTS preload (bonus)", 100, "hsts-preload", 105},
		{"XCTO missing", 100, "xcto-missing", 95},
		{"XCTO invalid", 100, "xcto-invalid", 95},
		{"XFO present (bonus)", 100, "xfo-present", 105},
		{"XFO missing", 100, "xfo-missing", 80},
		{"XFO invalid", 100, "xfo-invalid", 80},
		{"CORP same-origin (bonus)", 100, "corp-same-origin", 110},
		{"CORP invalid", 100, "corp-invalid", 95},
		{"Unknown rule", 100, "unknown-rule", 100}, // Should not change
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.initialScore
			applyScorePenalty(&score, tt.rule)
			if score != tt.expectedScore {
				t.Errorf("applyScorePenalty(%d, %q) = %d, want %d",
					tt.initialScore, tt.rule, score, tt.expectedScore)
			}
		})
	}
}

// TestApplyObservatoryScoring tests the full Observatory scoring logic with correct expected values
func TestApplyObservatoryScoring(t *testing.T) {
	tests := []struct {
		name          string
		result        *Result
		isHTTPS       bool
		expectedScore int
		expectedGrade string
		explanation   string
	}{
		{
			name: "Perfect security headers",
			result: &Result{
				Score: 100,
				PresentHeaders: []HeaderInfo{
					{Name: "Content-Security-Policy", Value: "default-src 'self'"},
					{
						Name:  "Strict-Transport-Security",
						Value: "max-age=31536000; includeSubDomains; preload",
					},
					{Name: "X-Content-Type-Options", Value: "nosniff"},
					{Name: "X-Frame-Options", Value: "DENY"},
					{Name: "Referrer-Policy", Value: "strict-origin-when-cross-origin"},
					{Name: "Cross-Origin-Resource-Policy", Value: "same-origin"},
				},
				Cookies: []CookieInfo{
					{Name: "session", Secure: true, HttpOnly: true, SameSite: "Strict"},
				},
			},
			isHTTPS:       true,
			expectedScore: 130,
			expectedGrade: "A+",
			explanation:   "100 + 5 (cookies secure) + 5 (referrer private) + 5 (hsts preload) + 5 (xfo present) + 10 (corp same-origin) = 130",
		},
		{
			name: "No security headers on HTTPS",
			result: &Result{
				Score:          100,
				PresentHeaders: []HeaderInfo{},
			},
			isHTTPS:       true,
			expectedScore: 30,
			expectedGrade: "D",
			explanation:   "100 - 25 (csp missing) - 20 (hsts missing) - 5 (xcto missing) - 20 (xfo missing) = 30",
		},
		{
			name: "No security headers on HTTP",
			result: &Result{
				Score:          100,
				PresentHeaders: []HeaderInfo{},
			},
			isHTTPS:       false,
			expectedScore: 50,
			expectedGrade: "C",
			explanation:   "100 - 25 (csp missing) - 5 (xcto missing) - 20 (xfo missing) = 50 (no HSTS penalty on HTTP)",
		},
		{
			name: "CSP with unsafe-inline",
			result: &Result{
				Score: 100,
				PresentHeaders: []HeaderInfo{
					{
						Name:   "Content-Security-Policy",
						Value:  "script-src 'unsafe-inline'",
						Issues: []string{"script-src contains 'unsafe-inline'"},
					},
				},
			},
			isHTTPS:       true,
			expectedScore: 35,
			expectedGrade: "D",
			explanation:   "100 - 20 (csp unsafe-inline) - 20 (hsts missing) - 5 (xcto missing) - 20 (xfo missing) = 35",
		},
		{
			name: "CSP with unsafe-eval",
			result: &Result{
				Score: 100,
				PresentHeaders: []HeaderInfo{
					{
						Name:   "Content-Security-Policy",
						Value:  "script-src 'unsafe-eval'",
						Issues: []string{"script-src contains 'unsafe-eval'"},
					},
				},
			},
			isHTTPS:       true,
			expectedScore: 45,
			expectedGrade: "C-",
			explanation:   "100 - 10 (csp unsafe-eval) - 20 (hsts missing) - 5 (xcto missing) - 20 (xfo missing) = 45",
		},
		{
			name: "Insecure session cookie",
			result: &Result{
				Score: 100,
				Cookies: []CookieInfo{
					{Name: "sessionid", Secure: false, HttpOnly: true, SameSite: "Lax"},
				},
			},
			isHTTPS:       true,
			expectedScore: 0,
			expectedGrade: "F",
			explanation:   "100 - 40 (session no secure) - 25 (csp missing) - 20 (hsts missing) - 5 (xcto missing) - 20 (xfo missing) = -10 → 0 (capped)",
		},
		{
			name: "CORS wildcard with credentials",
			result: &Result{
				Score: 100,
				CORS: &CORSInfo{
					AllowOrigin:      "*",
					AllowCredentials: true,
					Issues: []string{
						"CRITICAL: Allow-Origin '*' with Allow-Credentials is a CSRF vulnerability",
					},
				},
			},
			isHTTPS:       true,
			expectedScore: 0,
			expectedGrade: "F",
			explanation:   "100 - 50 (cors critical) - 25 (csp missing) - 20 (hsts missing) - 5 (xcto missing) - 20 (xfo missing) = -20 → 0 (capped)",
		},
		{
			name: "CSP with frame-ancestors",
			result: &Result{
				Score: 100,
				PresentHeaders: []HeaderInfo{
					{
						Name:  "Content-Security-Policy",
						Value: "default-src 'self'; frame-ancestors 'none'",
					},
				},
			},
			isHTTPS:       true,
			expectedScore: 80,
			expectedGrade: "B+",
			explanation:   "100 + 5 (xfo bonus via csp frame-ancestors) - 20 (hsts missing) - 5 (xcto missing) = 80",
		},
		{
			name: "HSTS with preload",
			result: &Result{
				Score: 100,
				PresentHeaders: []HeaderInfo{
					{
						Name:  "Strict-Transport-Security",
						Value: "max-age=31536000; includeSubDomains; preload",
					},
				},
			},
			isHTTPS:       true,
			expectedScore: 55,
			expectedGrade: "C",
			explanation:   "100 + 5 (hsts preload) - 25 (csp missing) - 5 (xcto missing) - 20 (xfo missing) = 55",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyObservatoryScoring(tt.result, tt.isHTTPS)
			tt.result.Grade = scoreToGrade(tt.result.Score)

			if tt.result.Score != tt.expectedScore {
				t.Errorf("Score mismatch:\n  got:  %d (grade: %s)\n  want: %d (grade: %s)\n  %s",
					tt.result.Score, tt.result.Grade,
					tt.expectedScore, tt.expectedGrade,
					tt.explanation)
			}

			if tt.result.Grade != tt.expectedGrade {
				t.Errorf("Grade mismatch: got %s, want %s (score: %d)",
					tt.result.Grade, tt.expectedGrade, tt.result.Score)
			}
		})
	}
}

// TestGetHeaderByName tests the header lookup function
func TestGetHeaderByName(t *testing.T) {
	headers := []HeaderInfo{
		{Name: "Content-Security-Policy", Value: "default-src 'self'"},
		{Name: "Strict-Transport-Security", Value: "max-age=31536000"},
		{Name: "X-Content-Type-Options", Value: "nosniff"},
	}

	tests := []struct {
		name       string
		headers    []HeaderInfo
		searchName string
		want       *HeaderInfo
	}{
		{
			name:       "Find existing header",
			headers:    headers,
			searchName: "Content-Security-Policy",
			want:       &headers[0],
		},
		{
			name:       "Find with different case",
			headers:    headers,
			searchName: "content-security-policy",
			want:       &headers[0],
		},
		{
			name:       "Header not found",
			headers:    headers,
			searchName: "X-Frame-Options",
			want:       nil,
		},
		{
			name:       "Empty headers list",
			headers:    []HeaderInfo{},
			searchName: "Any-Header",
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getHeaderByName(tt.headers, tt.searchName)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("getHeaderByName() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Name != tt.want.Name {
				t.Errorf("getHeaderByName() name = %s, want %s", got.Name, tt.want.Name)
			}
		})
	}
}

// TestScoringIntegration tests the full scoring integration with HTTP server
func TestScoringIntegration(t *testing.T) {
	// Create a test server with good security headers
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	checker := New(&Options{
		Timeout:    10,
		DisableSSL: true,
		Method:     "GET",
	})

	result := checker.Check(ts.URL)

	if result.Error != "" {
		t.Fatalf("Check failed: %s", result.Error)
	}

	// Should have a high score with good security headers
	if result.Score < 100 {
		t.Errorf("Expected score >= 100 for good security, got %d (grade: %s)",
			result.Score, result.Grade)
	}

	// Should have an A+ or A grade
	if result.Grade != "A+" && result.Grade != "A" { //nolint:goconst // test comparison
		t.Errorf("Expected grade A+ or A for good security, got %s", result.Grade)
	}
}

// TestScoringIntegrationPoorSecurity tests scoring with poor security
func TestScoringIntegrationPoorSecurity(t *testing.T) {
	// Create a test server with no security headers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately no security headers
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	checker := New(&Options{
		Timeout: 10,
		Method:  "GET",
	})

	result := checker.Check(ts.URL)

	if result.Error != "" {
		t.Fatalf("Check failed: %s", result.Error)
	}

	// Should have a low score with no security headers
	if result.Score > 50 {
		t.Errorf("Expected score <= 50 for poor security, got %d (grade: %s)",
			result.Score, result.Grade)
	}

	// Should have a low grade
	if result.Grade == "A+" || result.Grade == "A" ||
		result.Grade == "B+" {
		t.Errorf("Expected low grade for poor security, got %s", result.Grade)
	}
}
