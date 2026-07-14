package csrf

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// CSRFModule implements CSRF vulnerability scanning
type CSRFModule struct{}

// NewCSRFModule creates a new CSRF module
func NewCSRFModule() *CSRFModule {
	return &CSRFModule{}
}

func (m *CSRFModule) Name() string        { return "csrf" }
func (m *CSRFModule) Description() string  { return "Cross-Site Request Forgery (CSRF) vulnerability scanner" }

// Scan scans an endpoint for CSRF vulnerabilities
func (m *CSRFModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Only check forms for CSRF
	for _, form := range endpoint.Forms {
		// Check if form has CSRF token
		hasCSRFToken := false
		csrfTokenNames := []string{
			"csrf", "xsrf", "token", "_token", "authenticity_token",
			"csrf_token", "xsrf_token", "_csrf", "anti-csrf",
		}

		for inputName := range form.Inputs {
			lowerName := strings.ToLower(inputName)
			for _, csrfName := range csrfTokenNames {
				if strings.Contains(lowerName, csrfName) {
					hasCSRFToken = true
					break
				}
			}
			if hasCSRFToken {
				break
			}
		}

		// If no CSRF token found, it might be vulnerable
		if !hasCSRFToken && strings.ToUpper(form.Method) == "POST" {
			// Check if form action is relative (same origin)
			isRelative := !strings.HasPrefix(form.Action, "http://") && !strings.HasPrefix(form.Action, "https://")

			severity := scanner.SeverityMedium
			if isRelative {
				severity = scanner.SeverityHigh
			}

			vuln := scanner.Vulnerability{
				Type:     "CSRF",
				Severity: severity,
				URL:      form.Action,
				Description: "Form missing CSRF protection token",
				Details: map[string]string{
					"method":       form.Method,
					"is_relative":  fmt.Sprintf("%v", isRelative),
					"input_count":  fmt.Sprintf("%d", len(form.Inputs)),
				},
				Timestamp: utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for SameSite cookie attribute
	resp, err := client.Get(endpoint.URL)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.SameSite != http.SameSiteDefaultMode {
			// Cookie has SameSite attribute, which helps prevent CSRF
			continue
		}

		// Check if cookie is session-related
		cookieName := strings.ToLower(cookie.Name)
		if strings.Contains(cookieName, "session") || strings.Contains(cookieName, "sid") || strings.Contains(cookieName, "auth") {
			vuln := scanner.Vulnerability{
				Type:     "CSRF",
				Severity: scanner.SeverityLow,
				URL:      endpoint.URL,
				Description: "Session cookie without SameSite attribute",
				Details: map[string]string{
					"cookie_name": cookie.Name,
				},
				Timestamp: utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}
