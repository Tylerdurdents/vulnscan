# VulnScan API Documentation

This document provides detailed API documentation for VulnScan's packages.

## Table of Contents

- [cmd](#cmd)
- [pkg/utils](#pkgutils)
- [pkg/crawler](#pkgcrawler)
- [pkg/scanner](#pkgscanner)
- [pkg/modules](#pkgmodules)
- [pkg/reporter](#pkgreporter)
- [pkg/proxy](#pkgproxy)
- [internal/db](#internaldb)

## cmd

The main CLI package using Cobra framework.

### Commands

#### `vulnscan crawl [target]`

Crawl a target URL and discover endpoints.

**Flags:**
- `-d, --depth int` - Maximum crawl depth (default 3)
- `-H, --headless` - Use headless browser for JS-heavy sites
- `-o, --output string` - Output file path (default "endpoints.json")
- `-t, --threads int` - Number of concurrent threads (default 5)

#### `vulnscan scan [target]`

Scan a target URL for vulnerabilities.

**Flags:**
- `-a, --auth string` - Authentication value (token, cookie, user:pass)
- `--auth-type string` - Authentication type (cookie, bearer, basic, header)
- `--auth-header string` - Custom header name for header auth type
- `-d, --depth int` - Maximum crawl depth (default 3)
- `-f, --format string` - Report format (json, csv, html) (default "json")
- `-H, --headless` - Use headless browser for JS-heavy sites
- `-m, --modules strings` - Modules to use (default [sqli,xss])
- `-o, --output string` - Output file path (default "report.json")
- `-r, --rate-limit int` - Rate limit (requests per second, 0 = unlimited)
- `-p, --payloads string` - Custom payloads file path
- `--resume string` - Resume scan from state file
- `--db string` - SQLite database path for storing results

#### `vulnscan proxy [target]`

Start a proxy server to capture and analyze traffic.

**Flags:**
- `-a, --addr string` - Listen address (default ":8080")
- `-v, --verbose` - Verbose output

## pkg/utils

Utility functions and HTTP client.

### HTTPClient

```go
type HTTPClient struct {
    Client    *http.Client
    UserAgent string
    Headers   map[string]string
    Cookies   []*http.Cookie
    Limiter   *RateLimiter
    Cache     *ResponseCache
}
```

#### Functions

```go
func NewHTTPClient(timeout time.Duration, insecureSkipVerify bool) *HTTPClient
func NewHTTPClientWithPool(timeout time.Duration, insecureSkipVerify bool, pool PoolConfig) *HTTPClient
func (c *HTTPClient) SetUserAgent(ua string)
func (c *HTTPClient) SetHeader(key, value string)
func (c *HTTPClient) SetCookie(name, value string)
func (c *HTTPClient) SetBearerToken(token string)
func (c *HTTPClient) SetBasicAuth(username, password string)
func (c *HTTPClient) SetAuthConfig(config AuthConfig)
func (c *HTTPClient) SetRateLimit(requestsPerSecond, burst int)
func (c *HTTPClient) EnableCache(ttl time.Duration, maxSize int)
func (c *HTTPClient) DisableCache()
func (c *HTTPClient) Get(targetURL string) (*http.Response, error)
func (c *HTTPClient) Post(targetURL string, data url.Values) (*http.Response, error)
func (c *HTTPClient) PostJSON(targetURL string, body string) (*http.Response, error)
func (c *HTTPClient) DoRequest(method, targetURL string, body io.Reader) (*http.Response, error)
```

### AuthConfig

```go
type AuthConfig struct {
    Type   string // "cookie", "bearer", "basic", "header"
    Value  string
    Header string
}
```

### PoolConfig

```go
type PoolConfig struct {
    MaxIdleConns        int
    MaxIdleConnsPerHost int
    MaxConnsPerHost     int
    IdleConnTimeout     time.Duration
}
```

### RateLimiter

```go
type RateLimiter struct {
    rate     int
    burst    int
    tokens   int
    lastTime time.Time
}

func NewRateLimiter(rate, burst int) *RateLimiter
func (r *RateLimiter) Wait()
```

### ResponseCache

```go
type ResponseCache struct {
    entries map[string]*CacheEntry
    ttl     time.Duration
    maxSize int
}

func NewResponseCache(ttl time.Duration, maxSize int) *ResponseCache
func (c *ResponseCache) Get(key string) (*CacheEntry, bool)
func (c *ResponseCache) Set(key string, statusCode int, headers http.Header, body []byte)
func (c *ResponseCache) Delete(key string)
func (c *ResponseCache) Clear()
func (c *ResponseCache) Size() int
```

### Helpers

```go
func NormalizeURL(rawURL string) (string, error)
func GetBaseURL(rawURL string) (string, error)
func IsSameDomain(url1, url2 string) bool
func ExtractParams(rawURL string) map[string]string
func InjectParam(rawURL, param, value string) (string, error)
func ContainsPattern(input, pattern string) bool
func UniqueStrings(slice []string) []string
func JoinURL(base, path string) string
func ExtractContext(body, match string) string
func CompileRegex(pattern string) (*regexp.Regexp, error)
func GetCurrentTime() time.Time
```

### Payloads

```go
type Payload struct {
    Value       string
    Pattern     string
    Description string
}

func LoadPayloadsFromFile(filePath string) ([]Payload, error)
func LoadStringsFromFile(filePath string) ([]string, error)
```

## pkg/crawler

Web crawler for discovering endpoints.

### CrawlerConfig

```go
type CrawlerConfig struct {
    MaxDepth   int
    MaxPages   int
    Threads    int
    Timeout    time.Duration
    UserAgent  string
    IgnoreRobots bool
    SameDomain bool
}
```

### Endpoint

```go
type Endpoint struct {
    URL        string            `json:"url"`
    Method     string            `json:"method"`
    Params     map[string]string `json:"params,omitempty"`
    Forms      []Form            `json:"forms,omitempty"`
    Depth      int               `json:"depth"`
    Source     string            `json:"source"`
}
```

### Form

```go
type Form struct {
    Action string            `json:"action"`
    Method string            `json:"method"`
    Inputs map[string]string `json:"inputs"`
}
```

### Functions

```go
func NewCrawler(config CrawlerConfig) *Crawler
func (c *Crawler) Crawl(targetURL string) ([]Endpoint, error)
```

## pkg/scanner

Vulnerability scanner.

### ScannerConfig

```go
type ScannerConfig struct {
    Threads    int
    Timeout    time.Duration
    UserAgent  string
    Modules    []string
    Auth       utils.AuthConfig
    RateLimit  int
    ResumeFile string
}
```

### Severity

```go
type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)
```

### Vulnerability

```go
type Vulnerability struct {
    ID          string            `json:"id"`
    Type        string            `json:"type"`
    Severity    Severity          `json:"severity"`
    URL         string            `json:"url"`
    Parameter   string            `json:"parameter,omitempty"`
    Payload     string            `json:"payload,omitempty"`
    Description string            `json:"description"`
    Evidence    string            `json:"evidence,omitempty"`
    Details     map[string]string `json:"details,omitempty"`
    Timestamp   time.Time         `json:"timestamp"`
}
```

### ScanResult

```go
type ScanResult struct {
    Target          string          `json:"target"`
    Endpoints       int             `json:"endpoints"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    StartTime       time.Time       `json:"start_time"`
    EndTime         time.Time       `json:"end_time"`
    Duration        time.Duration   `json:"duration"`
}
```

### Module Interface

```go
type Module interface {
    Name() string
    Description() string
    Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []Vulnerability
}
```

### Functions

```go
func NewScanner(config ScannerConfig) *Scanner
func (s *Scanner) RegisterModule(module Module)
func (s *Scanner) Scan(endpoints []crawler.Endpoint) (*ScanResult, error)
func SaveScanState(state *ScanState, filePath string) error
func LoadScanState(filePath string) (*ScanState, error)
```

## pkg/modules

Vulnerability scanning modules.

### Available Modules

| Module | Name | Description |
|--------|------|-------------|
| SQLi | `sqli` | SQL Injection detection |
| XSS | `xss` | Cross-Site Scripting detection |
| CMDI | `cmdi` | Command Injection detection |
| CSRF | `csrf` | Cross-Site Request Forgery detection |
| LFI | `lfi` | Local File Inclusion detection |
| Open Redirect | `openredirect` | Open Redirect detection |
| SSRF | `ssrf` | Server-Side Request Forgery detection |
| SSTI | `ssti` | Server-Side Template Injection detection |
| XXE | `xxe` | XML External Entity detection |
| JWT | `jwt` | JWT vulnerability detection |
| CORS | `cors` | CORS misconfiguration detection |
| Headers | `headers` | Security headers detection |

### Functions

```go
func GetAllModules() []scanner.Module
func GetModulesWithPayloads(payloadFile string) ([]scanner.Module, error)
func GetModuleByName(name string) scanner.Module
func LoadCustomPayloads(filePath string) ([]utils.Payload, error)
```

## pkg/reporter

Report generation.

### ReportFormat

```go
type ReportFormat string

const (
    FormatJSON ReportFormat = "json"
    FormatCSV  ReportFormat = "csv"
    FormatHTML ReportFormat = "html"
)
```

### Functions

```go
func NewReporter(format ReportFormat, output string) *Reporter
func (r *Reporter) Generate(result *scanner.ScanResult) error
```

## pkg/proxy

HTTP proxy for traffic capture.

### ProxyConfig

```go
type ProxyConfig struct {
    ListenAddr string
    TargetURL  string
    Verbose    bool
}
```

### Transaction

```go
type Transaction struct {
    Request  Request  `json:"request"`
    Response Response `json:"response"`
    Duration int64    `json:"duration_ms"`
}
```

### Functions

```go
func NewProxy(config ProxyConfig) *Proxy
func (p *Proxy) Start() error
func (p *Proxy) Stop() error
func (p *Proxy) GetTransactions() []Transaction
```

## internal/db

Database operations.

### Functions

```go
func NewDB(dbPath string) (*DB, error)
func (db *DB) Close() error
func (db *DB) SaveScan(result *scanner.ScanResult) (int64, error)
func (db *DB) GetScan(scanID int64) (*scanner.ScanResult, error)
func (db *DB) GetRecentScans(limit int) ([]scanner.ScanResult, error)
```
