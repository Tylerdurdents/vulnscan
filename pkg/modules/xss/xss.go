package xss

import (
	"io"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// XSSModule implements Cross-Site Scripting vulnerability scanning
type XSSModule struct{}

// NewXSSModule creates a new XSS module
func NewXSSModule() *XSSModule {
	return &XSSModule{}
}

func (m *XSSModule) Name() string        { return "xss" }
func (m *XSSModule) Description() string  { return "Cross-Site Scripting (XSS) vulnerability scanner" }

// Scan scans an endpoint for XSS vulnerabilities
func (m *XSSModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// XSS payloads
	payloads := []struct {
		payload  string
		pattern  string
		severity scanner.Severity
		desc     string
	}{
		{
			payload:  "<script>alert('XSS')</script>",
			pattern:  "<script>alert\\('XSS'\\)</script>",
			severity: scanner.SeverityHigh,
			desc:     "Reflected XSS via script tag",
		},
		{
			payload:  "<img src=x onerror=alert('XSS')>",
			pattern:  "onerror=alert\\('XSS'\\)",
			severity: scanner.SeverityHigh,
			desc:     "Reflected XSS via img onerror",
		},
		{
			payload:  "javascript:alert('XSS')",
			pattern:  "javascript:alert\\('XSS'\\)",
			severity: scanner.SeverityHigh,
			desc:     "Reflected XSS via javascript protocol",
		},
		{
			payload:  "\"><script>alert('XSS')</script>",
			pattern:  "<script>alert\\('XSS'\\)</script>",
			severity: scanner.SeverityHigh,
			desc:     "Reflected XSS via attribute breakout",
		},
		{
			payload:  "'-alert('XSS')-'",
			pattern:  "alert\\('XSS'\\)",
			severity: scanner.SeverityMedium,
			desc:     "Reflected XSS via string injection",
		},
	}

	// Test each parameter
	for param, value := range endpoint.Params {
		for _, p := range payloads {
			// Inject payload into parameter
			testURL, err := utils.InjectParam(endpoint.URL, param, value+p.payload)
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

			// Check if payload is reflected in response
			if strings.Contains(bodyStr, p.payload) || utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "XSS",
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
						formData[k] = v + p.payload
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
						Type:        "XSS",
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
