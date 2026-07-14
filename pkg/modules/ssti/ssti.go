package ssti

import (
	"io"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SSTIModule implements Server-Side Template Injection vulnerability scanning
type SSTIModule struct {
	CustomPayloads []utils.Payload
}

// NewSSTIModule creates a new SSTI module
func NewSSTIModule() *SSTIModule {
	return &SSTIModule{}
}

// NewSSTIModuleWithPayloads creates a new SSTI module with custom payloads
func NewSSTIModuleWithPayloads(payloads []utils.Payload) *SSTIModule {
	return &SSTIModule{CustomPayloads: payloads}
}

func (m *SSTIModule) Name() string        { return "ssti" }
func (m *SSTIModule) Description() string  { return "Server-Side Template Injection (SSTI) vulnerability scanner" }

// Scan scans an endpoint for SSTI vulnerabilities
func (m *SSTIModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// SSTI payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "{{7*7}}",
			pattern:  "49",
			severity: scanner.SeverityHigh,
			desc:     "SSTI via Jinja2/Twig template",
		},
		{
			payload:  "${7*7}",
			pattern:  "49",
			severity: scanner.SeverityHigh,
			desc:     "SSTI via Freemarker/Velocity template",
		},
		{
			payload:  "<%= 7*7 %>",
			pattern:  "49",
			severity: scanner.SeverityHigh,
			desc:     "SSTI via ERB template",
		},
		{
			payload:  "{{constructor.constructor('return this')()}}",
			pattern:  "(?i)(global|process|require)",
			severity: scanner.SeverityCritical,
			desc:     "SSTI via prototype pollution",
		},
		{
			payload:  "#{7*7}",
			pattern:  "49",
			severity: scanner.SeverityHigh,
			desc:     "SSTI via Ruby template",
		},
	}

	// Add custom payloads
	for _, cp := range m.CustomPayloads {
		pattern := cp.Pattern
		if pattern == "" {
			pattern = "49"
		}
		desc := cp.Description
		if desc == "" {
			desc = "Custom SSTI payload"
		}
		payloads = append(payloads, struct {
			payload    string
			pattern    string
			severity   scanner.Severity
			desc       string
		}{
			payload:  cp.Value,
			pattern:  pattern,
			severity: scanner.SeverityHigh,
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

			// Check for SSTI patterns
			if strings.Contains(bodyStr, p.payload) || utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "SSTI",
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

				if strings.Contains(bodyStr, p.payload) || utils.ContainsPattern(bodyStr, p.pattern) {
					vuln := scanner.Vulnerability{
						Type:        "SSTI",
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
