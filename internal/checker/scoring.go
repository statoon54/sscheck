package checker

import "strings"

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
	XCTOMissing:              -5,
	XCTOInvalid:              -5,
	XFOPresent:               5,
	XFOMissing:               -20,
	XFOInvalid:               -20,
	CORPSameOrigin:           10,
	CORPInvalid:              -5,
}

// applyScorePenalty applies a scoring penalty/bonus based on the rule name
func applyScorePenalty(score *int, rule string) {
	switch rule {
	case "csp-missing":
		*score += observatoryRules.CSPMissing
	case "csp-unsafe-inline":
		*score += observatoryRules.CSPUnsafeInline
	case "csp-unsafe-eval":
		*score += observatoryRules.CSPUnsafeEval
	case "cookies-secure-all":
		*score += observatoryRules.CookiesSecureAll
	case "cookies-session-no-secure":
		*score += observatoryRules.CookiesSessionNoSecure
	case "cookies-session-no-httponly":
		*score += observatoryRules.CookiesSessionNoHttpOnly
	case "cookies-no-secure":
		*score += observatoryRules.CookiesNoSecure
	case "cookies-no-secure-hsts":
		*score += observatoryRules.CookiesNoSecureWithHSTS
	case "cors-wildcard-critical":
		*score += observatoryRules.CORSWildcardCritical
	case "referrer-private":
		*score += observatoryRules.ReferrerPrivate
	case "referrer-unsafe":
		*score += observatoryRules.ReferrerUnsafe
	case "hsts-missing":
		*score += observatoryRules.HSTSMissingHTTPS
	case "hsts-short":
		*score += observatoryRules.HSTSShortMaxAge
	case "hsts-preload":
		*score += observatoryRules.HSTSPreload
	case "xcto-missing":
		*score += observatoryRules.XCTOMissing
	case "xcto-invalid":
		*score += observatoryRules.XCTOInvalid
	case "xfo-present":
		*score += observatoryRules.XFOPresent
	case "xfo-missing":
		*score += observatoryRules.XFOMissing
	case "xfo-invalid":
		*score += observatoryRules.XFOInvalid
	case "corp-same-origin":
		*score += observatoryRules.CORPSameOrigin
	case "corp-invalid":
		*score += observatoryRules.CORPInvalid
	}
}

// applyObservatoryScoring applies Mozilla Observatory scoring based on already collected data
func applyObservatoryScoring(result *Result, isHTTPS bool) {
	// CSP scoring - check if present and for issues
	cspHeader := getHeaderByName(result.PresentHeaders, "Content-Security-Policy")
	if cspHeader == nil {
		applyScorePenalty(&result.Score, "csp-missing")
	} else {
		// CSP is present, check for unsafe directives in issues
		for _, issue := range cspHeader.Issues {
			if strings.Contains(issue, "unsafe-inline") && strings.Contains(issue, "script-src") {
				applyScorePenalty(&result.Score, "csp-unsafe-inline")
			}
			if strings.Contains(issue, "unsafe-eval") {
				applyScorePenalty(&result.Score, "csp-unsafe-eval")
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
			applyScorePenalty(&result.Score, "cookies-secure-all")
		} else if hasSessionWithoutSecure {
			applyScorePenalty(&result.Score, "cookies-session-no-secure")
		} else if hasSessionWithoutHttpOnly {
			applyScorePenalty(&result.Score, "cookies-session-no-httponly")
		} else if !hasSecureCookies {
			hstsHeader := getHeaderByName(result.PresentHeaders, "Strict-Transport-Security")
			if hstsHeader != nil {
				applyScorePenalty(&result.Score, "cookies-no-secure-hsts")
			} else {
				applyScorePenalty(&result.Score, "cookies-no-secure")
			}
		}
	}

	// CORS scoring - only if CORS was analyzed
	if result.CORS != nil {
		for _, issue := range result.CORS.Issues {
			if strings.Contains(issue, "CRITICAL") {
				applyScorePenalty(&result.Score, "cors-wildcard-critical")
				break
			}
		}
	}

	// Referrer-Policy scoring
	refHeader := getHeaderByName(result.PresentHeaders, "Referrer-Policy")
	if refHeader != nil {
		value := strings.ToLower(refHeader.Value)
		// Check for private values (bonus)
		privateValues := []string{
			"no-referrer",
			"same-origin",
			"strict-origin",
			"strict-origin-when-cross-origin",
		}
		for _, pv := range privateValues {
			if strings.Contains(value, pv) {
				applyScorePenalty(&result.Score, "referrer-private")
				break
			}
		}
		// Check for unsafe values (penalty)
		if strings.Contains(value, "unsafe-url") {
			applyScorePenalty(&result.Score, "referrer-unsafe")
		}
	}

	// HSTS scoring
	hstsHeader := getHeaderByName(result.PresentHeaders, "Strict-Transport-Security")
	if isHTTPS && hstsHeader == nil {
		applyScorePenalty(&result.Score, "hsts-missing")
	} else if hstsHeader != nil {
		// Check max-age duration
		for _, issue := range hstsHeader.Issues {
			if strings.Contains(issue, "less than 6 months") {
				applyScorePenalty(&result.Score, "hsts-short")
				break
			}
		}
		// Check for preload bonus
		value := strings.ToLower(hstsHeader.Value)
		if strings.Contains(value, "preload") && strings.Contains(value, "includesubdomains") {
			applyScorePenalty(&result.Score, "hsts-preload")
		}
	}

	// X-Content-Type-Options scoring
	xctoHeader := getHeaderByName(result.PresentHeaders, "X-Content-Type-Options")
	if xctoHeader == nil {
		applyScorePenalty(&result.Score, "xcto-missing")
	} else if len(xctoHeader.Issues) > 0 {
		applyScorePenalty(&result.Score, "xcto-invalid")
	}

	// X-Frame-Options scoring
	xfoHeader := getHeaderByName(result.PresentHeaders, "X-Frame-Options")
	cspFrameAncestors := cspHeader != nil &&
		strings.Contains(strings.ToLower(cspHeader.Value), "frame-ancestors")

	if xfoHeader != nil || cspFrameAncestors {
		applyScorePenalty(&result.Score, "xfo-present")
	} else {
		applyScorePenalty(&result.Score, "xfo-missing")
	}

	if xfoHeader != nil && len(xfoHeader.Issues) > 0 {
		applyScorePenalty(&result.Score, "xfo-invalid")
	}

	// Cross-Origin-Resource-Policy scoring
	corpHeader := getHeaderByName(result.PresentHeaders, "Cross-Origin-Resource-Policy")
	if corpHeader != nil {
		value := strings.ToLower(corpHeader.Value)
		if value == "same-origin" || value == "same-site" {
			applyScorePenalty(&result.Score, "corp-same-origin")
		} else if len(corpHeader.Issues) > 0 {
			applyScorePenalty(&result.Score, "corp-invalid")
		}
	}

	// Ensure score doesn't go below 0
	if result.Score < 0 {
		result.Score = 0
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
