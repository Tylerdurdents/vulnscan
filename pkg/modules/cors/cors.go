package cors

import (
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// CORSModule implements CORS misconfiguration vulnerability scanning
type CORSModule struct{}

// NewCORSModule creates a new CORS module
func NewCORSModule() *CORSModule {
	return &CORSModule{}
}

func (m *CORSModule) Name() string        { return "cors" }
func (m *CORSModule) Description() string  { return "CORS misconfiguration vulnerability scanner" }

// Scan scans an endpoint for CORS misconfigurations
func (m *CORSModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Test origins to check
	testOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"https://subdomain.evil.com",
		"null",
		"https://evil.com.attacker.com",
	}

	for _, origin := range testOrigins {
		// Set Origin header
		client.SetHeader("Origin", origin)
		
		resp, err := client.Get(endpoint.URL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check CORS headers
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "" {
			continue
		}

		// Check for wildcard with credentials
		if acao == "*" && strings.ToLower(acac) == "true" {
			vuln := scanner.Vulnerability{
				Type:     "CORS_WILDCARD_CREDENTIALS",
				Severity: scanner.SeverityCritical,
				URL:      endpoint.URL,
				Description: "CORS allows all origins with credentials - allows credential theft",
				Evidence:    "Access-Control-Allow-Origin: " + acao + ", Access-Control-Allow-Credentials: " + acac,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}

		// Check if origin is reflected
		if acao == origin {
			severity := scanner.SeverityHigh
			if strings.ToLower(acac) == "true" {
				severity = scanner.SeverityCritical
			}

			desc := "CORS reflects arbitrary origin"
			if strings.ToLower(acac) == "true" {
				desc += " with credentials - allows credential theft"
			}

			vuln := scanner.Vulnerability{
				Type:        "CORS_ORIGIN_REFLECTION",
				Severity:    severity,
				URL:         endpoint.URL,
				Description: desc,
				Evidence:    "Origin: " + origin + " -> Access-Control-Allow-Origin: " + acao,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}

		// Check for null origin
		if origin == "null" && acao == "null" {
			severity := scanner.SeverityHigh
			if strings.ToLower(acac) == "true" {
				severity = scanner.SeverityCritical
			}

			vuln := scanner.Vulnerability{
				Type:        "CORS_NULL_ORIGIN",
				Severity:    severity,
				URL:         endpoint.URL,
				Description: "CORS allows null origin - can be exploited via sandboxed iframe",
				Evidence:    "Access-Control-Allow-Origin: null",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}

		// Check for subdomain matching
		if strings.HasSuffix(acao, ".evil.com") || strings.HasSuffix(acao, ".attacker.com") {
			vuln := scanner.Vulnerability{
				Type:        "CORS_WILDCARD_SUBDOMAIN",
				Severity:    scanner.SeverityHigh,
				URL:         endpoint.URL,
				Description: "CORS allows arbitrary subdomains",
				Evidence:    "Access-Control-Allow-Origin: " + acao,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}
	}

	// Check for CORS misconfiguration via preflight
	if len(vulns) == 0 {
		req, _ := http.NewRequest("OPTIONS", endpoint.URL, nil)
		req.Header.Set("Origin", "https://evil.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		
		resp, err := client.DoRequest("OPTIONS", endpoint.URL, nil)
		if err == nil {
			defer resp.Body.Close()
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acam := resp.Header.Get("Access-Control-Allow-Methods")
			
			if acao == "https://evil.com" && strings.Contains(acam, "DELETE") {
				vuln := scanner.Vulnerability{
					Type:        "CORS_DANGEROUS_METHODS",
					Severity:    scanner.SeverityHigh,
					URL:         endpoint.URL,
					Description: "CORS allows dangerous methods from arbitrary origins",
					Evidence:    "Access-Control-Allow-Methods: " + acam,
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	// Remove test header
	delete(client.Headers, "Origin")

	return vulns
}
