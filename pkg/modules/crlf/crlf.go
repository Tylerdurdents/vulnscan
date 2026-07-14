package crlf

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// CRLFModule implements CRLF injection vulnerability scanning
type CRLFModule struct{}

// NewCRLFModule creates a new CRLF module
func NewCRLFModule() *CRLFModule {
	return &CRLFModule{}
}

func (m *CRLFModule) Name() string        { return "crlf" }
func (m *CRLFModule) Description() string  { return "CRLF injection vulnerability scanner" }

// Scan scans an endpoint for CRLF injection vulnerabilities
func (m *CRLFModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// CRLF payloads
	payloads := []struct {
		payload  string
		pattern  string
		severity scanner.Severity
		desc     string
	}{
		{
			payload:  "%0d%0aInjected-Header:injected",
			pattern:  "Injected-Header",
			severity: scanner.SeverityHigh,
			desc:     "CRLF injection via URL encoding",
		},
		{
			payload:  "\r\nInjected-Header:injected",
			pattern:  "Injected-Header",
			severity: scanner.SeverityHigh,
			desc:     "CRLF injection via raw CRLF",
		},
		{
			payload:  "%0d%0a%0d%0a<script>alert('XSS')</script>",
			pattern:  "<script>alert",
			severity: scanner.SeverityCritical,
			desc:     "CRLF injection leading to XSS",
		},
		{
			payload:  "%5cr%5cnInjected-Header:injected",
			pattern:  "Injected-Header",
			severity: scanner.SeverityHigh,
			desc:     "CRLF injection via double encoding",
		},
		{
			payload:  "%E5%98%8A%E5%98%8DInjected-Header:injected",
			pattern:  "Injected-Header",
			severity: scanner.SeverityHigh,
			desc:     "CRLF injection via Unicode encoding",
		},
	}

	// Test each parameter
	for param := range endpoint.Params {
		for _, p := range payloads {
			testURL, err := utils.InjectParam(endpoint.URL, param, p.payload)
			if err != nil {
				continue
			}

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check if injected header appears in response
			if resp.Header.Get("Injected-Header") != "" {
				vuln := scanner.Vulnerability{
					Type:        "CRLF_INJECTION",
					Severity:    p.severity,
					URL:         endpoint.URL,
					Parameter:   param,
					Payload:     p.payload,
					Description: p.desc,
					Evidence:    "Injected header found in response",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
				break
			}

			// Check response body for CRLF injection
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if strings.Contains(bodyStr, "Injected-Header") {
				vuln := scanner.Vulnerability{
					Type:        "CRLF_INJECTION",
					Severity:    p.severity,
					URL:         endpoint.URL,
					Parameter:   param,
					Payload:     p.payload,
					Description: p.desc,
					Evidence:    "Injected header found in response body",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
				break
			}
		}
	}

	// Test URL path for CRLF injection
	pathPayloads := []string{
		"/%0d%0aInjected-Header:injected",
		"/%0d%0a%0d%0a<script>alert('XSS')</script>",
	}

	for _, payload := range pathPayloads {
		testURL := strings.TrimRight(endpoint.URL, "/") + payload
		
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.Header.Get("Injected-Header") != "" {
			vuln := scanner.Vulnerability{
				Type:        "CRLF_INJECTION_PATH",
				Severity:    scanner.SeverityHigh,
				URL:         endpoint.URL,
				Parameter:   "URL path",
				Payload:     payload,
				Description: "CRLF injection via URL path",
				Evidence:    "Injected header found in response",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}
	}

	// Test headers for CRLF injection
	headerPayloads := []struct {
		header  string
		payload string
	}{
		{"Referer", "%0d%0aInjected-Header:injected"},
		{"User-Agent", "%0d%0aInjected-Header:injected"},
		{"X-Forwarded-For", "%0d%0aInjected-Header:injected"},
	}

	for _, hp := range headerPayloads {
		client.SetHeader(hp.header, hp.payload)
		
		resp, err := client.Get(endpoint.URL)
		if err != nil {
			delete(client.Headers, hp.header)
			continue
		}
		defer resp.Body.Close()

		if resp.Header.Get("Injected-Header") != "" {
			vuln := scanner.Vulnerability{
				Type:        "CRLF_INJECTION_HEADER",
				Severity:    scanner.SeverityHigh,
				URL:         endpoint.URL,
				Parameter:   hp.header,
				Payload:     hp.payload,
				Description: "CRLF injection via " + hp.header + " header",
				Evidence:    "Injected header found in response",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}

		delete(client.Headers, hp.header)
	}

	return vulns
}
