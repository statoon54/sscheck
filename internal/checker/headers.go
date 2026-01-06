package checker

// SecurityHeaders defines the security headers to check with their severity level
var SecurityHeaders = map[string]string{
	"X-XSS-Protection":                  "deprecated",
	"X-Frame-Options":                   "warning",
	"X-Content-Type-Options":            "warning",
	"Strict-Transport-Security":         "error",
	"Content-Security-Policy":           "warning",
	"X-Permitted-Cross-Domain-Policies": "deprecated",
	"Referrer-Policy":                   "warning",
	"Expect-CT":                         "deprecated",
	"Permissions-Policy":                "warning",
	"Cross-Origin-Embedder-Policy":      "warning",
	"Cross-Origin-Resource-Policy":      "warning",
	"Cross-Origin-Opener-Policy":        "warning",
}

// InformationHeaders are headers that might disclose sensitive information
var InformationHeaders = []string{
	"X-Powered-By",
	"Server",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
}

// CacheHeaders are headers related to caching
var CacheHeaders = []string{
	"Cache-Control",
	"Pragma",
	"Last-Modified",
	"Expires",
	"ETag",
}

// HeaderInfo contains information about a header
type HeaderInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Status   string `json:"status,omitempty"`   // ok, warning, error
	Severity string `json:"severity,omitempty"` // for missing headers
}
