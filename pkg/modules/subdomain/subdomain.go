package subdomain

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SubdomainModule implements subdomain takeover vulnerability scanning
type SubdomainModule struct{}

// NewSubdomainModule creates a new Subdomain module
func NewSubdomainModule() *SubdomainModule {
	return &SubdomainModule{}
}

func (m *SubdomainModule) Name() string        { return "subdomain" }
func (m *SubdomainModule) Description() string  { return "Subdomain takeover vulnerability scanner" }

// Scan scans an endpoint for subdomain takeover vulnerabilities
func (m *SubdomainModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Known vulnerable services and their fingerprints
	vulnerableServices := []struct {
		pattern string
		service string
	}{
		{"There isn't a GitHub Pages site here.", "GitHub Pages"},
		{"Repository not found", "GitHub Pages"},
		{"NoSuchBucket", "AWS S3"},
		{"The specified bucket does not exist", "AWS S3"},
		{"is not a registered InCloudustomer", "Heroku"},
		{"No such app", "Heroku"},
		{"is not a registered domain", "Shopify"},
		{"Sorry, this shop is currently unavailable", "Shopify"},
		{"Domain is not configured", "Fly.io"},
		{"The thing you were looking for is no longer here", "Tumblr"},
		{"Whatever you were looking for doesn't currently exist at this address", "Tumblr"},
		{"Do you want to register", "WordPress"},
		{"404 Not Found", "Various"},
		{"Fastly error: unknown domain", "Fastly"},
		{"The specified container does not exist", "Azure"},
		{"The account is suspended", "Squarespace"},
		{"No Site For Domain", "Pantheon"},
		{"The specified bucket does not exist", "Google Cloud Storage"},
		{"There is no app configured at that hostname", "CloudFoundry"},
		{"project not found", "Netlify"},
		{"402 Payment Required", "Stripe"},
	}

	resp, err := client.Get(endpoint.URL)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulns
	}
	bodyStr := string(body)

	// Check for CNAME-like behavior (custom domain pointing to service)
	for _, service := range vulnerableServices {
		if strings.Contains(bodyStr, service.pattern) {
			severity := scanner.SeverityHigh
			
			vuln := scanner.Vulnerability{
				Type:        "SUBDOMAIN_TAKEOVER",
				Severity:    severity,
				URL:         endpoint.URL,
				Description: "Possible subdomain takeover via " + service.service,
				Evidence:    "Found: " + service.pattern,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for common takeover indicators in headers
	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")

	takeoverHeaders := []struct {
		value   string
		service string
	}{
		{"AmazonS3", "AWS S3"},
		{"GitHub.com", "GitHub"},
		{"Heroku", "Heroku"},
		{"Fly.io", "Fly.io"},
		{"Netlify", "Netlify"},
		{"Vercel", "Vercel"},
	}

	for _, th := range takeoverHeaders {
		if strings.Contains(server, th.value) || strings.Contains(xPoweredBy, th.value) {
			// Check if the page shows an error (potential takeover)
			if strings.Contains(bodyStr, "404") || strings.Contains(bodyStr, "not found") || strings.Contains(bodyStr, "error") {
				vuln := scanner.Vulnerability{
					Type:        "SUBDOMAIN_TAKEOVER_POTENTIAL",
					Severity:    scanner.SeverityMedium,
					URL:         endpoint.URL,
					Description: "Potential subdomain takeover via " + th.service,
					Evidence:    "Server: " + server + " with error page",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
