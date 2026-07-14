package cmdi

import (
	"io"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// CMDIModule implements Command Injection vulnerability scanning
type CMDIModule struct{}

// NewCMDIModule creates a new Command Injection module
func NewCMDIModule() *CMDIModule {
	return &CMDIModule{}
}

func (m *CMDIModule) Name() string        { return "cmdi" }
func (m *CMDIModule) Description() string  { return "Command Injection vulnerability scanner" }

// Scan scans an endpoint for Command Injection vulnerabilities
func (m *CMDIModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Command injection payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload:  "; ls",
			pattern:  "(?i)(total \\d+|drwx|rwx|\\.txt|\\.conf|\\.log)",
			severity: scanner.SeverityCritical,
			desc:     "Command injection via semicolon",
		},
		{
			payload:  "| ls",
			pattern:  "(?i)(total \\d+|drwx|rwx|\\.txt|\\.conf|\\.log)",
			severity: scanner.SeverityCritical,
			desc:     "Command injection via pipe",
		},
		{
			payload:  "&& ls",
			pattern:  "(?i)(total \\d+|drwx|rwx|\\.txt|\\.conf|\\.log)",
			severity: scanner.SeverityCritical,
			desc:     "Command injection via AND operator",
		},
		{
			payload:  "`ls`",
			pattern:  "(?i)(total \\d+|drwx|rwx|\\.txt|\\.conf|\\.log)",
			severity: scanner.SeverityCritical,
			desc:     "Command injection via backticks",
		},
		{
			payload:  "$(ls)",
			pattern:  "(?i)(total \\d+|drwx|rwx|\\.txt|\\.conf|\\.log)",
			severity: scanner.SeverityCritical,
			desc:     "Command injection via command substitution",
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

			// Check for command output patterns
			if utils.ContainsPattern(bodyStr, p.pattern) {
				vuln := scanner.Vulnerability{
					Type:        "COMMAND_INJECTION",
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

				if utils.ContainsPattern(bodyStr, p.pattern) {
					vuln := scanner.Vulnerability{
						Type:        "COMMAND_INJECTION",
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
