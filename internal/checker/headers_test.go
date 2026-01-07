package checker

import (
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	// Verify all expected security headers are defined
	expectedHeaders := []string{
		"X-XSS-Protection",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Permitted-Cross-Domain-Policies",
		"Referrer-Policy",
		"Expect-CT",
		"Permissions-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Opener-Policy",
	}

	for _, header := range expectedHeaders {
		if _, ok := SecurityHeaders[header]; !ok {
			t.Errorf("SecurityHeaders missing %s", header)
		}
	}

	// Verify severity values are valid
	validSeverities := map[string]bool{
		"deprecated": true,
		"warning":    true,
		"error":      true,
	}

	for header, severity := range SecurityHeaders {
		if !validSeverities[severity] {
			t.Errorf("Invalid severity %s for header %s", severity, header)
		}
	}
}

func TestDeprecatedHeaders(t *testing.T) {
	deprecatedHeaders := []string{
		"X-XSS-Protection",
		"X-Permitted-Cross-Domain-Policies",
		"Expect-CT",
	}

	for _, header := range deprecatedHeaders {
		if severity, ok := SecurityHeaders[header]; !ok || severity != "deprecated" {
			t.Errorf("%s should be marked as deprecated", header)
		}
	}
}

func TestInformationHeaders(t *testing.T) {
	expectedInfoHeaders := []string{
		"X-Powered-By",
		"Server",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	if len(InformationHeaders) != len(expectedInfoHeaders) {
		t.Errorf(
			"InformationHeaders has %d entries, want %d",
			len(InformationHeaders),
			len(expectedInfoHeaders),
		)
	}

	for _, expected := range expectedInfoHeaders {
		found := false
		for _, header := range InformationHeaders {
			if header == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("InformationHeaders missing %s", expected)
		}
	}
}

func TestCacheHeaders(t *testing.T) {
	expectedCacheHeaders := []string{
		"Cache-Control",
		"Pragma",
		"Last-Modified",
		"Expires",
		"ETag",
	}

	if len(CacheHeaders) != len(expectedCacheHeaders) {
		t.Errorf(
			"CacheHeaders has %d entries, want %d",
			len(CacheHeaders),
			len(expectedCacheHeaders),
		)
	}

	for _, expected := range expectedCacheHeaders {
		found := false
		for _, header := range CacheHeaders {
			if header == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CacheHeaders missing %s", expected)
		}
	}
}

func TestHeaderInfoStruct(t *testing.T) {
	info := HeaderInfo{
		Name:     "Test-Header",
		Value:    "test-value",
		Status:   "ok",
		Severity: "warning",
	}

	if info.Name != "Test-Header" {
		t.Errorf("Name = %s, want Test-Header", info.Name)
	}
	if info.Value != "test-value" {
		t.Errorf("Value = %s, want test-value", info.Value)
	}
	if info.Status != "ok" {
		t.Errorf("Status = %s, want ok", info.Status)
	}
	if info.Severity != "warning" {
		t.Errorf("Severity = %s, want warning", info.Severity)
	}
}

func TestReferrerPolicyConstants(t *testing.T) {
	// Verify unsafe policies are defined
	expectedUnsafe := []string{
		"unsafe-url",
		"origin",
		"origin-when-cross-origin",
		"no-referrer-when-downgrade",
	}
	for _, expected := range expectedUnsafe {
		found := false
		for _, policy := range ReferrerPolicyUnsafe {
			if policy == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ReferrerPolicyUnsafe missing %s", expected)
		}
	}

	// Verify safe policies are defined
	expectedPrivate := []string{
		"no-referrer",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
	}
	for _, expected := range expectedPrivate {
		found := false
		for _, policy := range ReferrerPolicyPrivate {
			if policy == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ReferrerPolicyPrivate missing %s", expected)
		}
	}
}

func TestHSTSMinMaxAge(t *testing.T) {
	// 6 months in seconds = 15768000
	if HSTSMinMaxAge != 15768000 {
		t.Errorf("HSTSMinMaxAge = %d, want 15768000", HSTSMinMaxAge)
	}
}

func TestSessionCookieNames(t *testing.T) {
	// Verify common session cookie names are defined
	expectedNames := []string{"session", "phpsessid", "jsessionid", "auth", "token"}
	for _, expected := range expectedNames {
		found := false
		for _, name := range SessionCookieNames {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SessionCookieNames missing %s", expected)
		}
	}
}

func TestCSRFCookieNames(t *testing.T) {
	// Verify common CSRF cookie names are defined
	expectedNames := []string{"csrf", "csrftoken", "xsrf"}
	for _, expected := range expectedNames {
		found := false
		for _, name := range CSRFCookieNames {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CSRFCookieNames missing %s", expected)
		}
	}
}

func TestCookieInfoStruct(t *testing.T) {
	info := CookieInfo{
		Name:     "session",
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
		Path:     "/",
		Issues:   []string{"test issue"},
	}

	if info.Name != "session" {
		t.Errorf("Name = %s, want session", info.Name)
	}
	if !info.Secure {
		t.Error("Secure should be true")
	}
	if !info.HttpOnly {
		t.Error("HttpOnly should be true")
	}
	if info.SameSite != "Strict" {
		t.Errorf("SameSite = %s, want Strict", info.SameSite)
	}
	if info.Path != "/" {
		t.Errorf("Path = %s, want /", info.Path)
	}
	if len(info.Issues) != 1 || info.Issues[0] != "test issue" {
		t.Errorf("Issues = %v, want [test issue]", info.Issues)
	}
}

func TestCORSInfoStruct(t *testing.T) {
	info := CORSInfo{
		AllowOrigin:      "*",
		AllowCredentials: true,
		AllowMethods:     "GET, POST",
		AllowHeaders:     "Content-Type",
		Issues:           []string{"wildcard origin"},
	}

	if info.AllowOrigin != "*" {
		t.Errorf("AllowOrigin = %s, want *", info.AllowOrigin)
	}
	if !info.AllowCredentials {
		t.Error("AllowCredentials should be true")
	}
	if info.AllowMethods != "GET, POST" {
		t.Errorf("AllowMethods = %s, want GET, POST", info.AllowMethods)
	}
	if info.AllowHeaders != "Content-Type" {
		t.Errorf("AllowHeaders = %s, want Content-Type", info.AllowHeaders)
	}
	if len(info.Issues) != 1 || info.Issues[0] != "wildcard origin" {
		t.Errorf("Issues = %v, want [wildcard origin]", info.Issues)
	}
}
