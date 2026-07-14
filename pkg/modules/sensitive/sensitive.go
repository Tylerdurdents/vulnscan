package sensitive

import (
	"io"
	"regexp"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SensitiveModule implements sensitive data exposure vulnerability scanning
type SensitiveModule struct{}

// NewSensitiveModule creates a new Sensitive module
func NewSensitiveModule() *SensitiveModule {
	return &SensitiveModule{}
}

func (m *SensitiveModule) Name() string        { return "sensitive" }
func (m *SensitiveModule) Description() string  { return "Sensitive data exposure vulnerability scanner" }

// Scan scans an endpoint for sensitive data exposure
func (m *SensitiveModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

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

	// Sensitive data patterns
	sensitivePatterns := []struct {
		pattern  *regexp.Regexp
		name     string
		severity scanner.Severity
	}{
		{
			pattern:  regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
			name:     "Credit Card Number",
			severity: scanner.SeverityCritical,
		},
		{
			pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			name:     "Social Security Number (SSN)",
			severity: scanner.SeverityCritical,
		},
		{
			pattern:  regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			name:     "Email Address",
			severity: scanner.SeverityMedium,
		},
		{
			pattern:  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			name:     "IP Address",
			severity: scanner.SeverityLow,
		},
		{
			pattern:  regexp.MustCompile(`\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b`),
			name:     "Phone Number",
			severity: scanner.SeverityMedium,
		},
		{
			pattern:  regexp.MustCompile(`\b\d{1,5}\s[A-Za-z0-9\s,]+(?:Avenue|Ave|Street|St|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b`),
			name:     "Street Address",
			severity: scanner.SeverityMedium,
		},
		{
			pattern:  regexp.MustCompile(`\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b`),
			name:     "Date of Birth",
			severity: scanner.SeverityHigh,
		},
		{
			pattern:  regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`),
			name:     "IBAN",
			severity: scanner.SeverityHigh,
		},
	}

	// Check for sensitive data
	for _, sp := range sensitivePatterns {
		matches := sp.pattern.FindAllString(bodyStr, -1)
		if len(matches) > 0 {
			// Limit evidence to first match
			evidence := matches[0]
			if len(evidence) > 50 {
				evidence = evidence[:50] + "..."
			}

			vuln := scanner.Vulnerability{
				Type:        "SENSITIVE_DATA_EXPOSURE",
				Severity:    sp.severity,
				URL:         endpoint.URL,
				Description: "Exposed " + sp.name + " detected",
				Evidence:    evidence,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for debug information
	debugPatterns := []struct {
		pattern  string
		name     string
		severity scanner.Severity
	}{
		{"stack trace", "Stack Trace", scanner.SeverityHigh},
		{"exception", "Exception Details", scanner.SeverityMedium},
		{"traceback", "Python Traceback", scanner.SeverityHigh},
		{"at line", "Line Number Disclosure", scanner.SeverityMedium},
		{"debug mode", "Debug Mode", scanner.SeverityHigh},
		{"debug = true", "Debug Enabled", scanner.SeverityHigh},
		{"display_errors = On", "PHP Error Display", scanner.SeverityHigh},
		{"phpinfo()", "PHP Info", scanner.SeverityHigh},
		{"php_info()", "PHP Info", scanner.SeverityHigh},
		{"var_dump(", "PHP var_dump", scanner.SeverityMedium},
		{"print_r(", "PHP print_r", scanner.SeverityLow},
		{"console.log(", "JavaScript console.log", scanner.SeverityLow},
		{"System.out.print", "Java System.out", scanner.SeverityLow},
	}

	bodyLower := strings.ToLower(bodyStr)
	for _, dp := range debugPatterns {
		if strings.Contains(bodyLower, strings.ToLower(dp.pattern)) {
			vuln := scanner.Vulnerability{
				Type:        "DEBUG_INFORMATION",
				Severity:    dp.severity,
				URL:         endpoint.URL,
				Description: dp.name + " detected in response",
				Evidence:    "Found: " + dp.pattern,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for sensitive files
	sensitiveFiles := []struct {
		path     string
		name     string
		severity scanner.Severity
	}{
		{"/robots.txt", "Robots.txt", scanner.SeverityLow},
		{"/sitemap.xml", "Sitemap", scanner.SeverityLow},
		{"/.git/HEAD", "Git Repository", scanner.SeverityCritical},
		{"/.svn/entries", "SVN Repository", scanner.SeverityCritical},
		{"/.hg/dirstate", "Mercurial Repository", scanner.SeverityCritical},
		{"/backup.zip", "Backup File", scanner.SeverityCritical},
		{"/backup.sql", "Database Backup", scanner.SeverityCritical},
		{"/dump.sql", "Database Dump", scanner.SeverityCritical},
		{"/database.sql", "Database Dump", scanner.SeverityCritical},
		{"/db.sql", "Database Dump", scanner.SeverityCritical},
		{"/.DS_Store", "macOS DS_Store", scanner.SeverityMedium},
		{"/Thumbs.db", "Windows Thumbs.db", scanner.SeverityMedium},
		{"/.htaccess", "Apache htaccess", scanner.SeverityHigh},
		{"/web.config", "IIS Web Config", scanner.SeverityHigh},
	}

	for _, sf := range sensitiveFiles {
		testURL := strings.TrimRight(endpoint.URL, "/") + sf.path
		sfResp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer sfResp.Body.Close()

		if sfResp.StatusCode == 200 {
			sfBody, _ := io.ReadAll(sfResp.Body)
			if len(sfBody) > 0 {
				vuln := scanner.Vulnerability{
					Type:        "SENSITIVE_FILE",
					Severity:    sf.severity,
					URL:         testURL,
					Description: sf.name + " exposed",
					Evidence:    "File accessible",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
