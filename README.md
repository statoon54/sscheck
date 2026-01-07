# sscheck - Security Headers Check

A Go implementation of [shcheck](https://github.com/santoru/shcheck) - a tool to analyze HTTP security headers on web servers.

## Features

- 🔒 Check for security headers on websites
- 🎨 Beautiful TUI with [Bubbletea](https://github.com/charmbracelet/bubbletea)
- 🚀 Fast concurrent scanning with worker pools
- 📊 JSON output support
- 🔧 Customizable headers and methods
- 🌐 Proxy support
- 📁 Batch scanning from file
- 🍪 Cookie security analysis (Secure, HttpOnly, SameSite flags)
- 🌍 CORS configuration analysis
- 🛡️ In-depth security policy analysis (inspired by [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring))
- 📊 **Mozilla Observatory Scoring System** with grades (A+ to F)

## Security Headers Checked

| Header | Severity | Analysis |
| -------- | ---------- | -------- |
| Strict-Transport-Security (HSTS) | Error | max-age validation (≥6 months), preload requirements |
| Content-Security-Policy (CSP) | Warning | unsafe-inline, unsafe-eval, data:, broad sources, missing directives |
| X-Frame-Options | Warning | ALLOW-FROM deprecation warning |
| X-Content-Type-Options | Warning | Must be 'nosniff' |
| Referrer-Policy | Warning | Unsafe policy detection, multiple values support |
| Permissions-Policy | Warning | |
| Cross-Origin-Embedder-Policy | Warning | |
| Cross-Origin-Resource-Policy | Warning | cross-origin warning |
| Cross-Origin-Opener-Policy | Warning | |
| X-XSS-Protection | Deprecated | |
| X-Permitted-Cross-Domain-Policies | Deprecated | |
| Expect-CT | Deprecated | |

## Installation

```bash
go install github.com/statoon54/sscheck@latest
```

Or build from source:

```bash
git clone https://github.com/statoon54/sscheck.git
cd sscheck
go build -o sscheck .
```

## Usage

### Basic Usage

```bash
# Check a single target
sscheck https://example.com

# Check multiple targets
sscheck https://example.com https://google.com https://github.com

# Interactive TUI mode
sscheck -i https://example.com

# Load targets from file
sscheck --hfile targets.txt
```

### Options

```bash
Usage:
  sscheck [targets...] [flags]

Flags:
  -c, --cookie string        Set cookies for the request
      --cookies              Display cookie security analysis
      --cors                 Display CORS configuration analysis
  -k, --deprecated           Display deprecated headers
  -d, --disable-ssl          Disable SSL/TLS certificate validation
  -f, --follow               Follow redirects (default true)
  -H, --header stringArray   Add custom headers (format: 'Header: value')
      --hfile string         Load a list of hosts from a file
  -h, --help                 help for sscheck
  -I, --info                 Display information disclosure headers
  -i, --interactive          Run in interactive mode with TUI
  -j, --json                 Output results in JSON format
  -m, --method string        HTTP method to use (HEAD, GET, POST, PUT, DELETE) (default "HEAD")
  -p, --port string          Set a custom port to connect to
      --proxy string         Set a proxy (e.g., http://127.0.0.1:8080)
  -t, --timeout int          Request timeout in seconds (default 10)
  -w, --workers int          Number of concurrent workers (default 10)
  -x, --cache                Display caching headers
```

### Examples

```bash
# Check with custom port
sscheck -p 8443 https://example.com

# Check with custom headers
sscheck -H "Authorization: Bearer token" https://api.example.com

# Check with cookies
sscheck -c "session=abc123" https://example.com

# Use GET method instead of HEAD
sscheck -m GET https://example.com

# Show all information (info + cache + deprecated)
sscheck -I -x -k https://example.com

# JSON output for scripting
sscheck -j https://example.com | jq '.[] | .missing_headers'

# Through a proxy
sscheck --proxy http://127.0.0.1:8080 https://example.com

# Disable SSL verification
sscheck -d https://self-signed.example.com

# Batch scan with 20 workers
sscheck -w 20 --hfile large-hosts.txt

# Cookie security analysis (use -m GET to receive cookies)
sscheck --cookies -m GET https://example.com

# CORS configuration analysis (CORS headers are typically on APIs)
sscheck --cors -m GET https://api.example.com

# Full security analysis
sscheck --cookies --cors -m GET -I -x -k https://example.com
```

## Interactive Mode

Run with `-i` for a beautiful terminal UI:

```bash
sscheck -i https://example.com https://google.com
```

Controls:

- `↑/↓` or `j/k`: Navigate between results
- `a`: Toggle show all headers
- `q` or `Esc`: Quit

## Security Analysis

sscheck performs in-depth security analysis inspired by [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring):

### Mozilla Observatory Scoring System

Each target receives a **score (0-145+)** and a **grade (A+ to F)** based on security header implementation:

#### Baseline Score

- Starting score: **100 points**

#### Penalties (reduced score)

- Missing CSP: **-25**
- CSP with `unsafe-inline` in script-src: **-20**
- CSP with `unsafe-eval`: **-10**
- Missing HSTS (on HTTPS): **-20**
- HSTS max-age < 6 months: **-10**
- Missing X-Content-Type-Options: **-5**
- Missing X-Frame-Options: **-20**
- Invalid headers: **-5 to -20**
- Session cookie without Secure flag: **-40**
- Session cookie without HttpOnly: **-30**
- Non-session cookies without Secure: **-5 to -20**
- CORS wildcard with credentials (CRITICAL): **-50**

#### Bonuses (increased score)

- All cookies secure + HttpOnly + SameSite: **+5**
- Private referrer policy (no-referrer, strict-origin, etc.): **+5**
- HSTS with `preload` + `includeSubDomains`: **+5**
- X-Frame-Options present or CSP frame-ancestors: **+5**
- Cross-Origin-Resource-Policy same-origin/same-site: **+10**

#### Grade Scale

| Grade | Score Range |
|-------|-------------|
| **A+** | 100+ |
| **A**  | 90-99 |
| **A-** | 85-89 |
| **B+** | 80-84 |
| **B**  | 70-79 |
| **B-** | 65-69 |
| **C+** | 60-64 |
| **C**  | 50-59 |
| **C-** | 45-49 |
| **D+** | 40-44 |
| **D**  | 30-39 |
| **D-** | 25-29 |
| **F**  | 0-24 |

#### Example Output

```bash
$ sscheck github.com
[*] Analyzing headers of github.com
[*] Effective URL: https://github.com

[+] 5 security header(s) present
[-] 4 security header(s) missing
📊 Observatory Score: 115 | Grade: A+
```

### Content-Security-Policy (CSP)

- Detects `unsafe-inline` and `unsafe-eval` usage
- Warns about `data:` URI schemes
- Identifies overly broad sources (`*`, `http:`, `https:`)
- Checks for missing critical directives (`default-src`, `script-src`, `object-src`)

### Strict-Transport-Security (HSTS)

- Validates `max-age` (minimum 6 months / 15768000 seconds)
- Detects `max-age=0` which disables HSTS
- Warns if `preload` is set without `includeSubDomains`
- **Bonus**: +5 points for `preload` + `includeSubDomains` (HSTS preload list eligible)

### Cookie Security (`--cookies`)

- Checks for `Secure` flag (required for HTTPS)
- Checks for `HttpOnly` flag
- Validates `SameSite` attribute (Strict, Lax, None)
- Identifies session cookies and CSRF tokens

### CORS Configuration (`--cors`)

- Detects wildcard origin (`*`) allowing any domain
- Warns about `Access-Control-Allow-Credentials: true` with wildcards
- Identifies `null` origin which can be exploited

### Referrer-Policy

- Detects unsafe policies (`unsafe-url`, `no-referrer-when-downgrade`)
- Supports multiple comma-separated values (uses last valid value)

### X-Frame-Options

- Warns about deprecated `ALLOW-FROM` directive (use CSP `frame-ancestors` instead)

### Cross-Origin-Resource-Policy

- Warns when set to `cross-origin` (most permissive)

## JSON Output Format

```json
[
  {
    "target": "https://example.com",
    "effective_url": "https://www.example.com/",
    "status_code": 200,
    "score": 115,
    "grade": "A+",
    "present_headers": [
      {"name": "Strict-Transport-Security", "value": "max-age=31536000", "status": "ok"}
    ],
    "missing_headers": [
      {"name": "Content-Security-Policy", "severity": "warning"}
    ],
    "cookies": [
      {
        "name": "session_id",
        "secure": true,
        "httponly": true,
        "samesite": "Strict",
        "path": "/",
        "issues": []
      }
    ],
    "cors": {
      "allow_origin": "*",
      "allow_credentials": "false",
      "allow_methods": "GET, POST",
      "allow_headers": "Content-Type",
      "issues": ["CORS allows all origins with wildcard (*)"]
    },
    "safe_count": 5,
    "unsafe_count": 3
  }
]
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

- Franck Paszkowski - Université de Lille

## Credits

- Inspired by [shcheck](https://github.com/santoru/shcheck) by santoru
- Security analysis based on [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
- Built with [Bubbletea](https://github.com/charmbracelet/bubbletea), [Lipgloss](https://github.com/charmbracelet/lipgloss) and [gookit/color](https://github.com/gookit/color)
