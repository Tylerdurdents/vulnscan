package headers

import (
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// HeadersModule implements security headers vulnerability scanning
type HeadersModule struct{}

// NewHeadersModule creates a new Headers module
func NewHeadersModule() *HeadersModule {
	return &HeadersModule{}
}

func (m *HeadersModule) Name() string        { return "headers" }
func (m *HeadersModule) Description() string  { return "Security headers vulnerability scanner" }

// Scan scans an endpoint for missing or misconfigured security headers
func (m *HeadersModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	resp, err := client.Get(endpoint.URL)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	// Check for missing security headers
	securityHeaders := []struct {
		name     string
		severity scanner.Severity
		desc     string
		check    func(string) bool
	}{
		{
			name:     "Strict-Transport-Security",
			severity: scanner.SeverityHigh,
			desc:     "Missing HSTS header - allows protocol downgrade attacks",
			check:    func(v string) bool { return v == "" },
		},
		{
			name:     "X-Content-Type-Options",
			severity: scanner.SeverityMedium,
			desc:     "Missing X-Content-Type-Options header - allows MIME sniffing",
			check:    func(v string) bool { return v == "" || strings.ToLower(v) != "nosniff" },
		},
		{
			name:     "X-Frame-Options",
			severity: scanner.SeverityMedium,
			desc:     "Missing X-Frame-Options header - allows clickjacking",
			check:    func(v string) bool { return v == "" },
		},
		{
			name:     "Content-Security-Policy",
			severity: scanner.SeverityMedium,
			desc:     "Missing Content-Security-Policy header - no XSS protection",
			check:    func(v string) bool { return v == "" },
		},
		{
			name:     "X-XSS-Protection",
			severity: scanner.SeverityLow,
			desc:     "Missing X-XSS-Protection header",
			check:    func(v string) bool { return v == "" },
		},
		{
			name:     "Referrer-Policy",
			severity: scanner.SeverityLow,
			desc:     "Missing Referrer-Policy header - may leak sensitive information",
			check:    func(v string) bool { return v == "" },
		},
		{
			name:     "Permissions-Policy",
			severity: scanner.SeverityLow,
			desc:     "Missing Permissions-Policy header",
			check:    func(v string) bool { return v == "" },
		},
	}

	for _, header := range securityHeaders {
		value := resp.Header.Get(header.name)
		if header.check(value) {
			vuln := scanner.Vulnerability{
				Type:        "MISSING_SECURITY_HEADER",
				Severity:    header.severity,
				URL:         endpoint.URL,
				Description: header.desc,
				Evidence:    header.name + ": " + value,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for dangerous headers
	dangerousHeaders := []struct {
		name     string
		severity scanner.Severity
		desc     string
		check    func(string) bool
	}{
		{
			name:     "Server",
			severity: scanner.SeverityLow,
			desc:     "Server header reveals technology information",
			check:    func(v string) bool { return v != "" },
		},
		{
			name:     "X-Powered-By",
			severity: scanner.SeverityLow,
			desc:     "X-Powered-By header reveals technology information",
			check:    func(v string) bool { return v != "" },
		},
		{
			name:     "X-AspNet-Version",
			severity: scanner.SeverityLow,
			desc:     "X-AspNet-Version header reveals technology information",
			check:    func(v string) bool { return v != "" },
		},
	}

	for _, header := range dangerousHeaders {
		value := resp.Header.Get(header.name)
		if header.check(value) {
			vuln := scanner.Vulnerability{
				Type:        "INFORMATION_DISCLOSURE_HEADER",
				Severity:    header.severity,
				URL:         endpoint.URL,
				Description: header.desc,
				Evidence:    header.name + ": " + value,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for weak HSTS configuration
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts != "" {
		if !strings.Contains(hsts, "includeSubDomains") {
			vuln := scanner.Vulnerability{
				Type:        "HSTS_MISSING_SUBDOMAINS",
				Severity:    scanner.SeverityLow,
				URL:         endpoint.URL,
				Description: "HSTS missing includeSubDomains directive",
				Evidence:    "Strict-Transport-Security: " + hsts,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}

		if !strings.Contains(hsts, "preload") {
			vuln := scanner.Vulnerability{
				Type:        "HSTS_MISSING_PRELOAD",
				Severity:    scanner.SeverityLow,
				URL:         endpoint.URL,
				Description: "HSTS missing preload directive",
				Evidence:    "Strict-Transport-Security: " + hsts,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for weak CSP
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		if strings.Contains(csp, "unsafe-inline") {
			vuln := scanner.Vulnerability{
				Type:        "CSP_UNSAFE_INLINE",
				Severity:    scanner.SeverityMedium,
				URL:         endpoint.URL,
				Description: "CSP allows unsafe-inline - weak XSS protection",
				Evidence:    "Content-Security-Policy: " + csp,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}

		if strings.Contains(csp, "unsafe-eval") {
			vuln := scanner.Vulnerability{
				Type:        "CSP_UNSAFE_EVAL",
				Severity:    scanner.SeverityMedium,
				URL:         endpoint.URL,
				Description: "CSP allows unsafe-eval - weak XSS protection",
				Evidence:    "Content-Security-Policy: " + csp,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}

		if strings.Contains(csp, "*") {
			vuln := scanner.Vulnerability{
				Type:        "CSP_WILDCARD",
				Severity:    scanner.SeverityMedium,
				URL:         endpoint.URL,
				Description: "CSP contains wildcard source - weak protection",
				Evidence:    "Content-Security-Policy: " + csp,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}
