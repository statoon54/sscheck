package checker

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var (
	// scriptRegex matches script tags with src attribute
	scriptRegex = regexp.MustCompile("(?i)<script[^>]*\\ssrc=[\"']([^\"']+)[\"'][^>]*>")
	// integrityRegex matches integrity attribute in script tags
	integrityRegex = regexp.MustCompile("(?i)\\sintegrity=[\"'][^\"']+[\"']")
)

// ObservatoryScoring defines the scoring rules for each header/configuration
type ObservatoryScoring struct {
	CSPMissing               int // -25
	CSPUnsafeInline          int // -20
	CSPUnsafeEval            int // -10
	CookiesSecureAll         int // +5 (bonus)
	CookiesSessionNoSecure   int // -40
	CookiesSessionNoHttpOnly int // -30
	CookiesNoSecure          int // -20
	CookiesNoSecureWithHSTS  int // -5
	CORSWildcardCritical     int // -50
	ReferrerPrivate          int // +5 (bonus)
	ReferrerUnsafe           int // -5
	HSTSMissingHTTPS         int // -20
	HSTSShortMaxAge          int // -10
	HSTSPreload              int // +5 (bonus)
	SRIMissing               int // -5
	SRIPresent               int // +5 (bonus)
	XCTOMissing              int // -5
	XCTOInvalid              int // -5
	XFOPresent               int // +5 (bonus)
	XFOMissing               int // -20
	XFOInvalid               int // -20
	CORPSameOrigin           int // +10 (bonus)
	CORPInvalid              int // -5
}

var observatoryRules = ObservatoryScoring{
	CSPMissing:               -25,
	CSPUnsafeInline:          -20,
	CSPUnsafeEval:            -10,
	CookiesSecureAll:         5,
	CookiesSessionNoSecure:   -40,
	CookiesSessionNoHttpOnly: -30,
	CookiesNoSecure:          -20,
	CookiesNoSecureWithHSTS:  -5,
	CORSWildcardCritical:     -50,
	ReferrerPrivate:          5,
	ReferrerUnsafe:           -5,
	HSTSMissingHTTPS:         -20,
	HSTSShortMaxAge:          -10,
	HSTSPreload:              5,
	SRIMissing:               -5,
	SRIPresent:               5,
	XCTOMissing:              -5,
	XCTOInvalid:              -5,
	XFOPresent:               5,
	XFOMissing:               -20,
	XFOInvalid:               -20,
	CORPSameOrigin:           10,
	CORPInvalid:              -5,
}

// createScoreRule creates a ScoreRule with description and modifier
func createScoreRule(rule string, applied bool) ScoreRule {
	var description string
	var modifier int

	switch rule {
	case "csp-missing":
		description = "CSP missing"
		modifier = observatoryRules.CSPMissing
	case "csp-unsafe-inline":
		description = "CSP implemented unsafely"
		modifier = observatoryRules.CSPUnsafeInline
	case "csp-unsafe-eval":
		description = "CSP unsafe-eval"
		modifier = observatoryRules.CSPUnsafeEval
	case "cookies-secure-all":
		description = "Cookies secure (bonus)"
		modifier = observatoryRules.CookiesSecureAll
	case "cookies-session-no-secure":
		description = "Session cookie without Secure flag"
		modifier = observatoryRules.CookiesSessionNoSecure
	case "cookies-session-no-httponly":
		description = "Session cookie without HttpOnly"
		modifier = observatoryRules.CookiesSessionNoHttpOnly
	case "cookies-no-secure":
		description = "Cookies without Secure flag"
		modifier = observatoryRules.CookiesNoSecure
	case "cookies-no-secure-hsts":
		description = "Cookies without Secure (HSTS enabled)"
		modifier = observatoryRules.CookiesNoSecureWithHSTS
	case "cors-wildcard-critical":
		description = "CORS wildcard with credentials"
		modifier = observatoryRules.CORSWildcardCritical
	case "referrer-private":
		description = "Referrer-Policy private (bonus)"
		modifier = observatoryRules.ReferrerPrivate
	case "referrer-unsafe":
		description = "Referrer-Policy unsafe"
		modifier = observatoryRules.ReferrerUnsafe
	case "hsts-missing":
		description = "HSTS missing"
		modifier = observatoryRules.HSTSMissingHTTPS
	case "hsts-short":
		description = "HSTS max-age too short"
		modifier = observatoryRules.HSTSShortMaxAge
	case "hsts-preload":
		description = "HSTS preload (bonus)"
		modifier = observatoryRules.HSTSPreload
	case "sri-missing":
		description = "SRI missing on external scripts"
		modifier = observatoryRules.SRIMissing
	case "sri-present":
		description = "SRI present (bonus)"
		modifier = observatoryRules.SRIPresent
	case "xcto-missing":
		description = "X-Content-Type-Options missing"
		modifier = observatoryRules.XCTOMissing
	case "xcto-invalid":
		description = "X-Content-Type-Options invalid"
		modifier = observatoryRules.XCTOInvalid
	case "xfo-present":
		description = "X-Frame-Options present (bonus)"
		modifier = observatoryRules.XFOPresent
	case "xfo-missing":
		description = "X-Frame-Options missing"
		modifier = observatoryRules.XFOMissing
	case "xfo-invalid":
		description = "X-Frame-Options invalid"
		modifier = observatoryRules.XFOInvalid
	case "corp-same-origin":
		description = "CORP same-origin (bonus)"
		modifier = observatoryRules.CORPSameOrigin
	case "corp-invalid":
		description = "CORP invalid"
		modifier = observatoryRules.CORPInvalid
	}

	return ScoreRule{
		Description: description,
		Modifier:    modifier,
		Applied:     applied,
	}
}

// applyScorePenalty applies a scoring penalty/bonus based on the rule name
func applyScorePenalty(score *int, rule string) {
	r := createScoreRule(rule, true)
	*score += r.Modifier
}

// applyObservatoryScoring applies Mozilla Observatory scoring based on already collected data
func applyObservatoryScoring(result *Result, isHTTPS bool, htmlContent string) {
	// Track bonuses separately - only apply if final score >= 90
	var bonuses []string
	result.ScoreRules = []ScoreRule{} // Initialize

	// CSP scoring - check if present and for issues
	cspHeader := getHeaderByName(result.PresentHeaders, "Content-Security-Policy")
	if cspHeader == nil {
		rule := createScoreRule("csp-missing", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	} else {
		// CSP is present, check for unsafe directives in issues
		// Mozilla Observatory applies -20 for:
		// 1. unsafe-inline in script-src
		// 2. data: in script-src
		// 3. overly broad sources (https:, http:, *) in script-src or object-src
		// 4. missing script-src or object-src (no default-src fallback)
		hasUnsafeImplementation := false
		hasUnsafeEval := false

		for _, issue := range cspHeader.Issues {
			issueLower := strings.ToLower(issue)

			// Check for unsafe implementation (-20)
			if !hasUnsafeImplementation {
				if (strings.Contains(issueLower, "unsafe-inline") && strings.Contains(issueLower, "script-src")) ||
					(strings.Contains(issueLower, "data:") && strings.Contains(issueLower, "script-src")) ||
					(strings.Contains(issueLower, "overly broad") && (strings.Contains(issueLower, "script-src") || strings.Contains(issueLower, "object-src"))) ||
					strings.Contains(issueLower, "missing script-src") ||
					strings.Contains(issueLower, "missing object-src") {
					rule := createScoreRule("csp-unsafe-inline", true)
					result.ScoreRules = append(result.ScoreRules, rule)
					result.Score += rule.Modifier
					hasUnsafeImplementation = true
				}
			}

			// Check for unsafe-eval (-10)
			if !hasUnsafeEval && strings.Contains(issueLower, "unsafe-eval") {
				rule := createScoreRule("csp-unsafe-eval", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
				hasUnsafeEval = true
			}
		}
	}

	// Cookie scoring - only if cookies were analyzed
	if len(result.Cookies) > 0 {
		hasSecureCookies := true
		hasHttpOnlySessions := true
		hasSameSite := true
		hasSessionWithoutSecure := false
		hasSessionWithoutHttpOnly := false

		for _, cookie := range result.Cookies {
			if !cookie.Secure {
				hasSecureCookies = false
				if isSessionCookie(cookie.Name) {
					hasSessionWithoutSecure = true
				}
			}
			if isSessionCookie(cookie.Name) && !cookie.HttpOnly {
				hasHttpOnlySessions = false
				hasSessionWithoutHttpOnly = true
			}
			if cookie.SameSite == "" {
				hasSameSite = false
			}
		}

		// Apply cookie scoring rules
		if hasSecureCookies && hasHttpOnlySessions && hasSameSite {
			rule := createScoreRule("cookies-secure-all", true)
			result.ScoreRules = append(result.ScoreRules, rule)
			result.Score += rule.Modifier
		} else if hasSessionWithoutSecure {
			rule := createScoreRule("cookies-session-no-secure", true)
			result.ScoreRules = append(result.ScoreRules, rule)
			result.Score += rule.Modifier
		} else if hasSessionWithoutHttpOnly {
			rule := createScoreRule("cookies-session-no-httponly", true)
			result.ScoreRules = append(result.ScoreRules, rule)
			result.Score += rule.Modifier
		} else if !hasSecureCookies {
			hstsHeader := getHeaderByName(result.PresentHeaders, "Strict-Transport-Security")
			if hstsHeader != nil {
				rule := createScoreRule("cookies-no-secure-hsts", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
			} else {
				rule := createScoreRule("cookies-no-secure", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
			}
		}
	}

	// CORS scoring - only if CORS was analyzed
	if result.CORS != nil {
		for _, issue := range result.CORS.Issues {
			if strings.Contains(issue, "CRITICAL") {
				rule := createScoreRule("cors-wildcard-critical", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
				break
			}
		}
	}

	// Referrer-Policy scoring
	refHeader := getHeaderByName(result.PresentHeaders, "Referrer-Policy")
	if refHeader != nil {
		// Parse value - multiple policies can be comma-separated, browser uses last valid one
		policies := strings.Split(refHeader.Value, ",")
		var lastPolicy string
		for i := len(policies) - 1; i >= 0; i-- {
			p := strings.TrimSpace(strings.ToLower(policies[i]))
			if p != "" {
				lastPolicy = p
				break
			}
		}

		if lastPolicy != "" {
			// Check for unsafe values first (penalty)
			hasUnsafe := false
			if slices.Contains(ReferrerPolicyUnsafe, lastPolicy) {
				rule := createScoreRule("referrer-unsafe", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
				hasUnsafe = true
			}

			// Check for private values (bonus - applied only if score >= 90 and no unsafe values)
			if !hasUnsafe {
				if slices.Contains(ReferrerPolicyPrivate, lastPolicy) {
					bonuses = append(bonuses, "referrer-private")
				}
			}
		}
	}
	// Note: Referrer-Policy not implemented = 0 (no penalty according to Mozilla docs)

	// HSTS scoring
	hstsHeader := getHeaderByName(result.PresentHeaders, "Strict-Transport-Security")
	if isHTTPS && hstsHeader == nil {
		rule := createScoreRule("hsts-missing", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	} else if hstsHeader != nil {
		// Check max-age duration
		for _, issue := range hstsHeader.Issues {
			if strings.Contains(issue, "less than 6 months") {
				rule := createScoreRule("hsts-short", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
				break
			}
		}
		// Check for preload bonus (applied only if score >= 90)
		value := strings.ToLower(hstsHeader.Value)
		if strings.Contains(value, "preload") && strings.Contains(value, "includesubdomains") {
			bonuses = append(bonuses, "hsts-preload")
		}
	}

	// X-Content-Type-Options scoring
	xctoHeader := getHeaderByName(result.PresentHeaders, "X-Content-Type-Options")
	if xctoHeader == nil {
		rule := createScoreRule("xcto-missing", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	} else if len(xctoHeader.Issues) > 0 {
		rule := createScoreRule("xcto-invalid", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	}

	// X-Frame-Options scoring
	xfoHeader := getHeaderByName(result.PresentHeaders, "X-Frame-Options")
	cspFrameAncestors := cspHeader != nil &&
		strings.Contains(strings.ToLower(cspHeader.Value), "frame-ancestors")

	if xfoHeader != nil || cspFrameAncestors {
		// Bonus for XFO implementation (applied only if score >= 90)
		bonuses = append(bonuses, "xfo-present")
	} else {
		rule := createScoreRule("xfo-missing", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	}

	if xfoHeader != nil && len(xfoHeader.Issues) > 0 {
		rule := createScoreRule("xfo-invalid", true)
		result.ScoreRules = append(result.ScoreRules, rule)
		result.Score += rule.Modifier
	}

	// Subresource Integrity (SRI) scoring
	// Only available with GET requests that return HTML content
	if htmlContent != "" {
		// Parse HTML to find external scripts
		externalScripts, scriptsWithSRI := analyzeScriptTags(htmlContent, result.EffectiveURL)
		if externalScripts > 0 {
			if scriptsWithSRI == externalScripts {
				// All external scripts have SRI (bonus - applied only if score >= 90)
				bonuses = append(bonuses, "sri-present")
			} else {
				// Some external scripts without SRI
				rule := createScoreRule("sri-missing", true)
				result.ScoreRules = append(result.ScoreRules, rule)
				result.Score += rule.Modifier
			}
		}
	}
	// Note: HEAD requests cannot assess SRI (HTML parsing required)

	// Cross-Origin-Resource-Policy scoring
	corpHeader := getHeaderByName(result.PresentHeaders, "Cross-Origin-Resource-Policy")
	if corpHeader != nil {
		value := strings.ToLower(corpHeader.Value)
		if value == "same-origin" || value == "same-site" {
			// Bonus for CORP implementation (applied only if score >= 90)
			bonuses = append(bonuses, "corp-same-origin")
		} else if len(corpHeader.Issues) > 0 {
			rule := createScoreRule("corp-invalid", true)
			result.ScoreRules = append(result.ScoreRules, rule)
			result.Score += rule.Modifier
		}
	}

	// Ensure score doesn't go below 0
	if result.Score < 0 {
		result.Score = 0
	}

	// Apply bonuses only if score >= 90 (Mozilla Observatory rule)
	if result.Score >= 90 {
		for _, bonus := range bonuses {
			rule := createScoreRule(bonus, true)
			result.ScoreRules = append(result.ScoreRules, rule)
			result.Score += rule.Modifier
		}
	} else {
		// Track bonuses that weren't applied
		for _, bonus := range bonuses {
			rule := createScoreRule(bonus, false)
			result.ScoreRules = append(result.ScoreRules, rule)
		}
	}
}

// scoreToGrade converts a score to Mozilla Observatory grade
func scoreToGrade(score int) string {
	switch {
	case score >= 100:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 85:
		return "A-"
	case score >= 80:
		return "B+"
	case score >= 70:
		return "B"
	case score >= 65:
		return "B-"
	case score >= 60:
		return "C+"
	case score >= 50:
		return "C"
	case score >= 45:
		return "C-"
	case score >= 40:
		return "D+"
	case score >= 30:
		return "D"
	case score >= 25:
		return "D-"
	default:
		return "F"
	}
}

// getHeaderByName finds a header in the result by name
func getHeaderByName(headers []HeaderInfo, name string) *HeaderInfo {
	for i := range headers {
		if strings.EqualFold(headers[i].Name, name) {
			return &headers[i]
		}
	}
	return nil
}

// analyzeScriptTags parses HTML to find external script tags and checks for SRI
func analyzeScriptTags(htmlContent, baseURL string) (externalScripts, scriptsWithSRI int) {
	matches := scriptRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := match[1]

		// Check if it's an external script (not relative path or data: URI)
		if isExternalScript(src, baseURL) {
			externalScripts++

			// Check if the full script tag contains integrity attribute
			fullTag := match[0]
			if integrityRegex.MatchString(fullTag) {
				scriptsWithSRI++
			}
		}
	}

	return externalScripts, scriptsWithSRI
}

// isExternalScript checks if a script src is external (different domain)
func isExternalScript(src, baseURL string) bool {
	// Data URIs are not external
	if strings.HasPrefix(src, "data:") {
		return false
	}

	// Relative paths are not external
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") &&
		!strings.HasPrefix(src, "//") {
		return false
	}

	// Protocol-relative URLs
	if strings.HasPrefix(src, "//") {
		src = "https:" + src
	}

	// Parse URLs to compare domains
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return true // Assume external if we can't parse
	}

	srcParsed, err := url.Parse(src)
	if err != nil {
		return true
	}

	// Compare hosts
	return baseURLParsed.Host != srcParsed.Host
}
