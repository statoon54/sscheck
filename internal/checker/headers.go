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
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Status   string   `json:"status,omitempty"`   // ok, warning, error
	Severity string   `json:"severity,omitempty"` // for missing headers
	Issues   []string `json:"issues,omitempty"`   // specific issues found
}

// CookieInfo contains information about a cookie's security
type CookieInfo struct {
	Name     string   `json:"name"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"http_only"`
	SameSite string   `json:"same_site"` // Strict, Lax, None, or empty
	Path     string   `json:"path,omitempty"`
	Issues   []string `json:"issues,omitempty"`
}

// CORSInfo contains CORS configuration analysis
type CORSInfo struct {
	AllowOrigin      string   `json:"allow_origin,omitempty"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowMethods     string   `json:"allow_methods,omitempty"`
	AllowHeaders     string   `json:"allow_headers,omitempty"`
	Issues           []string `json:"issues,omitempty"`
}

// RedirectionInfo contains redirection analysis
type RedirectionInfo struct {
	FromURL   string   `json:"from_url"`
	ToURL     string   `json:"to_url"`
	IsHTTPS   bool     `json:"is_https"`
	HopsCount int      `json:"hops_count"`
	Issues    []string `json:"issues,omitempty"`
}

// ScoreRule represents a scoring rule that was applied
type ScoreRule struct {
	Description string `json:"description"`
	Modifier    int    `json:"modifier"` // positive for bonus, negative for penalty
	Applied     bool   `json:"applied"`  // whether it was actually applied (for bonuses that require score >= 90)
}

// CSP directives that should be restricted
var CSPUnsafeValues = []string{
	"'unsafe-inline'",
	"'unsafe-eval'",
	"data:",
	"blob:",
}

// CSP directives that are too broad
var CSPBroadSources = []string{
	"https:",
	"http:",
	"*",
}

// CSP critical directives that should be defined
var CSPCriticalDirectives = []string{
	"script-src",
	"object-src",
	"default-src",
}

// ReferrerPolicyUnsafe contains unsafe referrer policy values
var ReferrerPolicyUnsafe = []string{
	"unsafe-url",
	"origin",
	"origin-when-cross-origin",
	"no-referrer-when-downgrade",
}

// ReferrerPolicyPrivate contains secure referrer policy values
var ReferrerPolicyPrivate = []string{
	"no-referrer",
	"same-origin",
	"strict-origin",
	"strict-origin-when-cross-origin",
}

// HSTSMinMaxAge is the minimum recommended max-age (6 months in seconds)
const HSTSMinMaxAge = 15768000

// SessionCookieNames contains common session cookie name patterns
var SessionCookieNames = []string{
	"session",
	"sessionid",
	"sess",
	"sid",
	"phpsessid",
	"jsessionid",
	"aspsessionid",
	"asp.net_sessionid",
	"cfid",
	"cftoken",
	"auth",
	"token",
	"jwt",
	"access_token",
	"refresh_token",
}

// CSRFCookieNames contains common CSRF token cookie name patterns
var CSRFCookieNames = []string{
	"csrf",
	"csrftoken",
	"_csrf",
	"xsrf",
	"xsrf-token",
	"_xsrf",
	"antiforgery",
	"__requestverificationtoken",
}
