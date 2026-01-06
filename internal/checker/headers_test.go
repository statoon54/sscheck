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
