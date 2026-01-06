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

## Security Headers Checked

| Header | Severity |
| -------- | ---------- |
| Strict-Transport-Security (HSTS) | Error |
| Content-Security-Policy (CSP) | Warning |
| X-Frame-Options | Warning |
| X-Content-Type-Options | Warning |
| Referrer-Policy | Warning |
| Permissions-Policy | Warning |
| Cross-Origin-Embedder-Policy | Warning |
| Cross-Origin-Resource-Policy | Warning |
| Cross-Origin-Opener-Policy | Warning |
| X-XSS-Protection | Deprecated |
| X-Permitted-Cross-Domain-Policies | Deprecated |
| Expect-CT | Deprecated |

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

## JSON Output Format

```json
[
  {
    "target": "https://example.com",
    "effective_url": "https://www.example.com/",
    "status_code": 200,
    "present_headers": [
      {"name": "Strict-Transport-Security", "value": "max-age=31536000", "status": "ok"}
    ],
    "missing_headers": [
      {"name": "Content-Security-Policy", "severity": "warning"}
    ],
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
- Built with [Bubbletea](https://github.com/charmbracelet/bubbletea) and [Lipgloss](https://github.com/charmbracelet/lipgloss) [gookit](https://github.com/gookit/color)
