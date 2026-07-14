# VulnScan - Advanced Web Vulnerability Scanner

A modular web vulnerability scanner with crawling, passive/active scanning, and reporting capabilities.

## Features

- **Web Crawling**: Automatically discover endpoints and forms
- **Vulnerability Scanning**: Multiple scanning modules for different vulnerability types
- **Reporting**: Generate reports in JSON, CSV, and HTML formats
- **Proxy**: Capture and analyze HTTP traffic
- **Modular Architecture**: Easy to extend with new scanning modules

## Supported Vulnerability Modules

- **SQLi**: SQL Injection detection
- **XSS**: Cross-Site Scripting detection
- **CMDI**: Command Injection detection
- **CSRF**: Cross-Site Request Forgery detection
- **LFI**: Local File Inclusion detection
- **Open Redirect**: Open Redirect detection
- **SSRF**: Server-Side Request Forgery detection
- **SSTI**: Server-Side Template Injection detection

## Installation

```bash
# Clone the repository
git clone https://github.com/eonedge/vulnscan.git
cd vulnscan

# Build the application
go build -o vulnscan ./cmd/

# Run tests
go test ./tests/ -v
```

## Usage

### Crawl a target

```bash
# Basic crawl
./vulnscan crawl https://example.com

# Crawl with custom options
./vulnscan crawl https://example.com -d 5 -t 10 -o endpoints.json
```

### Scan for vulnerabilities

```bash
# Basic scan
./vulnscan scan https://example.com

# Scan with specific modules
./vulnscan scan https://example.com -m sqli,xss,lfi

# Scan with HTML report
./vulnscan scan https://example.com -f html -o report.html
```

### Start proxy

```bash
# Start proxy server
./vulnscan proxy https://example.com

# Start proxy with custom address
./vulnscan proxy https://example.com -a :9090 -v
```

## Command Reference

### Global Flags

- `-h, --help`: Show help

### Crawl Command

- `-d, --depth int`: Maximum crawl depth (default 3)
- `-H, --headless`: Use headless browser for JS-heavy sites
- `-o, --output string`: Output file path (default "endpoints.json")
- `-t, --threads int`: Number of concurrent threads (default 5)

### Scan Command

- `-a, --auth string`: Authentication cookie or token
- `-d, --depth int`: Maximum crawl depth (default 3)
- `-f, --format string`: Report format (json, csv, html) (default "json")
- `-H, --headless`: Use headless browser for JS-heavy sites
- `-m, --modules strings`: Modules to use (default [sqli,xss])
- `-o, --output string`: Output file path (default "report.json")
- `-t, --threads int`: Number of concurrent threads (default 10)

### Proxy Command

- `-a, --addr string`: Listen address (default ":8080")
- `-v, --verbose`: Verbose output

## Project Structure

```
vulnscan/
├── cmd/                    # Command-line interface
│   ├── main.go            # Main entry point
│   ├── crawl.go           # Crawl command
│   ├── scan.go            # Scan command
│   └── proxy.go           # Proxy command
├── internal/              # Internal packages
│   └── db/                # Database operations
├── pkg/                   # Public packages
│   ├── crawler/           # Web crawler
│   ├── scanner/           # Vulnerability scanner
│   ├── modules/           # Scanning modules
│   │   ├── sqli/          # SQL Injection module
│   │   ├── xss/           # XSS module
│   │   ├── cmdi/          # Command Injection module
│   │   ├── csrf/          # CSRF module
│   │   ├── lfi/           # LFI module
│   │   ├── openredirect/  # Open Redirect module
│   │   ├── ssrf/          # SSRF module
│   │   └── ssti/          # SSTI module
│   ├── reporter/          # Report generation
│   ├── proxy/             # HTTP proxy
│   └── utils/             # Utility functions
├── tests/                 # Test files
├── go.mod                 # Go module file
└── README.md              # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for authorized security testing only. Always get proper authorization before scanning any website or application. The developers are not responsible for any misuse of this tool.
