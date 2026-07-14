package openredirect

import (
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// OpenRedirectModule implements Open Redirect vulnerability scanning
type OpenRedirectModule struct{}

// NewOpenRedirectModule creates a new Open Redirect module
func NewOpenRedirectModule() *OpenRedirectModule {
	return &OpenRedirectModule{}
}

func (m *OpenRedirectModule) Name() string        { return "openredirect" }
func (m *OpenRedirectModule) Description() string  { return "Open Redirect vulnerability scanner" }

// Scan scans an endpoint for Open Redirect vulnerabilities
func (m *OpenRedirectModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Open Redirect payloads
	payloads := []struct {
		payload    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "https://evil.com",
			severity: scanner.SeverityMedium,
			desc:     "Open redirect via absolute URL",
		},
		{
			payload:  "//evil.com",
			severity: scanner.SeverityMedium,
			desc:     "Open redirect via protocol-relative URL",
		},
		{
			payload:  "https://evil.com%00.legitimate.com",
			severity: scanner.SeverityMedium,
			desc:     "Open redirect via null byte injection",
		},
		{
			payload:  "https://legitimate.com@evil.com",
			severity: scanner.SeverityMedium,
			desc:     "Open redirect via @ sign",
		},
		{
			payload:  "javascript:alert('redirect')",
			severity: scanner.SeverityHigh,
			desc:     "Open redirect via javascript protocol",
		},
	}

	// Test each parameter
	for param := range endpoint.Params {
		for _, p := range payloads {
			// Inject payload into parameter
			testURL, err := utils.InjectParam(endpoint.URL, param, p.payload)
			if err != nil {
				continue
			}

			// Send request
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for redirect
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" && strings.Contains(location, "evil.com") {
					vuln := scanner.Vulnerability{
						Type:        "OPEN_REDIRECT",
						Severity:    p.severity,
						URL:         endpoint.URL,
						Parameter:   param,
						Payload:     p.payload,
						Description: p.desc,
						Evidence:    "Redirect to: " + location,
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}
