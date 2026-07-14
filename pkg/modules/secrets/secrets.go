package secrets

import (
	"io"
	"regexp"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// SecretsModule implements secrets detection vulnerability scanning
type SecretsModule struct{}

// NewSecretsModule creates a new Secrets module
func NewSecretsModule() *SecretsModule {
	return &SecretsModule{}
}

func (m *SecretsModule) Name() string        { return "secrets" }
func (m *SecretsModule) Description() string  { return "Secrets detection vulnerability scanner" }

// Scan scans an endpoint for exposed secrets
func (m *SecretsModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
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

	// Secret patterns
	secretPatterns := []struct {
		pattern *regexp.Regexp
		name    string
		severity scanner.Severity
	}{
		{
			pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`),
			name:    "API Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`),
			name:    "Secret Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`),
			name:    "Access Token",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)(auth[_-]?token|authtoken)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`),
			name:    "Auth Token",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)(private[_-]?key|privatekey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?`),
			name:    "Private Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
			name:    "Private Key (PEM)",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)password\s*[:=]\s*['"]?([^\s'"]{8,})['"]?`),
			name:    "Password",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['"]?([A-Z0-9]{20})['"]?`),
			name:    "AWS Access Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`),
			name:    "AWS Secret Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)github[_-]?token\s*[:=]\s*['"]?(ghp_[a-zA-Z0-9]{36})['"]?`),
			name:    "GitHub Token",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)slack[_-]?token\s*[:=]\s*['"]?(xox[bpsa]-[a-zA-Z0-9-]+)['"]?`),
			name:    "Slack Token",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)stripe[_-]?secret[_-]?key\s*[:=]\s*['"]?(sk_live_[a-zA-Z0-9]{24,})['"]?`),
			name:    "Stripe Secret Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)google[_-]?api[_-]?key\s*[:=]\s*['"]?(AIza[a-zA-Z0-9_-]{35})['"]?`),
			name:    "Google API Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
			name:    "Heroku API Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*['"]?(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})['"]?`),
			name:    "SendGrid API Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['"]?(key-[a-zA-Z0-9]{32})['"]?`),
			name:    "Mailgun API Key",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)twilio[_-]?account[_-]?sid\s*[:=]\s*['"]?(AC[a-zA-Z0-9]{32})['"]?`),
			name:    "Twilio Account SID",
			severity: scanner.SeverityHigh,
		},
		{
			pattern: regexp.MustCompile(`(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['"]?([a-zA-Z0-9]{32})['"]?`),
			name:    "Twilio Auth Token",
			severity: scanner.SeverityCritical,
		},
		{
			pattern: regexp.MustCompile(`(?i)firebase[_-]?api[_-]?key\s*[:=]\s*['"]?(AIza[a-zA-Z0-9_-]{35})['"]?`),
			name:    "Firebase API Key",
			severity: scanner.SeverityHigh,
		},
	}

	// Check for secrets
	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllStringSubmatch(bodyStr, -1)
		for _, match := range matches {
			evidence := match[0]
			if len(match) > 1 {
				// Mask the secret value
				evidence = strings.Replace(match[0], match[1], "***REDACTED***", 1)
			}

			vuln := scanner.Vulnerability{
				Type:        "EXPOSED_SECRET",
				Severity:    sp.severity,
				URL:         endpoint.URL,
				Description: "Exposed " + sp.name + " detected",
				Evidence:    evidence,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for .env file exposure
	envPaths := []string{"/.env", "/env", "/env.example", "/env.local"}
	for _, path := range envPaths {
		testURL := strings.TrimRight(endpoint.URL, "/") + path
		envResp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer envResp.Body.Close()

		if envResp.StatusCode == 200 {
			envBody, _ := io.ReadAll(envResp.Body)
			envStr := string(envBody)

			if strings.Contains(envStr, "=") && (strings.Contains(envStr, "KEY") || strings.Contains(envStr, "SECRET") || strings.Contains(envStr, "PASSWORD")) {
				vuln := scanner.Vulnerability{
					Type:        "ENV_FILE_EXPOSED",
					Severity:    scanner.SeverityCritical,
					URL:         testURL,
					Description: "Environment file exposed - may contain secrets",
					Evidence:    "Found environment variables",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	// Check for common config file exposure
	configPaths := []string{
		"/config.php", "/config.json", "/config.yml", "/config.yaml",
		"/wp-config.php", "/settings.json", "/application.yml",
		"/database.yml", "/db.json", "/secrets.json",
	}

	for _, path := range configPaths {
		testURL := strings.TrimRight(endpoint.URL, "/") + path
		configResp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer configResp.Body.Close()

		if configResp.StatusCode == 200 {
			configBody, _ := io.ReadAll(configResp.Body)
			configStr := string(configBody)

			if len(configStr) > 10 { // Not an empty response
				vuln := scanner.Vulnerability{
					Type:        "CONFIG_FILE_EXPOSED",
					Severity:    scanner.SeverityHigh,
					URL:         testURL,
					Description: "Configuration file exposed",
					Evidence:    "File accessible at " + path,
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
