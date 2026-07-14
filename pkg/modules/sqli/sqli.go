package sqli

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SQLiModule implements SQL injection vulnerability scanning
type SQLiModule struct{}

// NewSQLiModule creates a new SQL injection module
func NewSQLiModule() *SQLiModule {
	return &SQLiModule{}
}

func (m *SQLiModule) Name() string        { return "sqli" }
func (m *SQLiModule) Description() string  { return "SQL Injection vulnerability scanner" }

// Scan scans an endpoint for SQL injection vulnerabilities
func (m *SQLiModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// SQL injection payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "'",
			pattern:  "(?i)(sql syntax|mysql|sqlite|postgresql|oracle|syntax error|unterminated|exception)",
			severity: scanner.SeverityHigh,
			desc:     "Classic SQL injection via single quote",
		},
		{
			payload:  "' OR '1'='1",
			pattern:  "(?i)(sql syntax|mysql|sqlite|postgresql|oracle|syntax error|unterminated|exception)",
			severity: scanner.SeverityHigh,
			desc:     "SQL injection via OR true condition",
		},
		{
			payload:  "1' ORDER BY 1--",
			pattern:  "(?i)(sql syntax|mysql|sqlite|postgresql|oracle|syntax error|unterminated|exception)",
			severity: scanner.SeverityHigh,
			desc:     "SQL injection via ORDER BY",
		},
		{
			payload:  "1' UNION SELECT NULL--",
			pattern:  "(?i)(sql syntax|mysql|sqlite|postgresql|oracle|syntax error|unterminated|exception)",
			severity: scanner.SeverityCritical,
			desc:     "SQL injection via UNION SELECT",
		},
		{
			payload:  "1; WAITFOR DELAY '0:0:5'--",
			pattern:  "(?i)(sql syntax|mysql|sqlite|postgresql|oracle|syntax error|unterminated|exception)",
			severity: scanner.SeverityCritical,
			desc:     "Time-based blind SQL injection",
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

			// Check for SQL error patterns
			if utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "SQL_INJECTION",
					Severity:    p.severity,
					URL:         endpoint.URL,
					Parameter:   param,
					Payload:     p.payload,
					Description: p.desc,
					Evidence:    extractEvidence(bodyStr, p.pattern),
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

				if utils.ContainsPattern(bodyStr, p.pattern) {
					vuln := scanner.Vulnerability{
						Type:        "SQL_INJECTION",
						Severity:    p.severity,
						URL:         form.Action,
						Parameter:   param,
						Payload:     p.payload,
						Description: p.desc + " (form submission)",
						Evidence:    extractEvidence(bodyStr, p.pattern),
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

// extractEvidence extracts the evidence of vulnerability from the response
func extractEvidence(body, pattern string) string {
	re, err := utils.CompileRegex(pattern)
	if err != nil {
		return ""
	}

	match := re.FindString(body)
	if match != "" {
		// Get surrounding context
		idx := strings.Index(body, match)
		start := idx - 50
		if start < 0 {
			start = 0
		}
		end := idx + len(match) + 50
		if end > len(body) {
			end = len(body)
		}
		return fmt.Sprintf("...%s...", body[start:end])
	}
	return ""
}
