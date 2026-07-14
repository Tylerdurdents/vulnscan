package dirlisting

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// DirListingModule implements directory listing vulnerability scanning
type DirListingModule struct{}

// NewDirListingModule creates a new DirListing module
func NewDirListingModule() *DirListingModule {
	return &DirListingModule{}
}

func (m *DirListingModule) Name() string        { return "dirlisting" }
func (m *DirListingModule) Description() string  { return "Directory listing vulnerability scanner" }

// Scan scans an endpoint for directory listing vulnerabilities
func (m *DirListingModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Common directory paths to check
	dirPaths := []string{
		"/",
		"/images/",
		"/img/",
		"/uploads/",
		"/upload/",
		"/files/",
		"/static/",
		"/assets/",
		"/backup/",
		"/backups/",
		"/temp/",
		"/tmp/",
		"/data/",
		"/log/",
		"/logs/",
		"/admin/",
		"/wp-content/",
		"/wp-includes/",
		"/wp-admin/",
		"/cgi-bin/",
		"/scripts/",
		"/css/",
		"/js/",
		"/javascript/",
		"/media/",
		"/docs/",
		"/documentation/",
		"/api/",
		"/v1/",
		"/v2/",
	}

	// Directory listing indicators
	indicators := []string{
		"Index of",
		"Directory listing for",
		"Parent Directory",
		"<title>Index of",
		"Last modified</th>",
		"Name</th><th>Last modified</th>",
		"\\\\ Volume Serial Number",
		"Directory of",
		"<pre>",
	}

	baseURL := strings.TrimRight(endpoint.URL, "/")

	for _, dirPath := range dirPaths {
		testURL := baseURL + dirPath

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Check for directory listing indicators
		for _, indicator := range indicators {
			if strings.Contains(bodyStr, indicator) {
				vuln := scanner.Vulnerability{
					Type:        "DIRECTORY_LISTING",
					Severity:    scanner.SeverityMedium,
					URL:         testURL,
					Description: "Directory listing enabled",
					Evidence:    "Found: " + indicator,
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
				break
			}
		}
	}

	// Check for sensitive directories
	sensitiveDirs := []struct {
		path     string
		name     string
		severity scanner.Severity
	}{
		{"/.git/", "Git Directory", scanner.SeverityCritical},
		{"/.svn/", "SVN Directory", scanner.SeverityCritical},
		{"/.hg/", "Mercurial Directory", scanner.SeverityCritical},
		{"/.env/", "Environment Directory", scanner.SeverityCritical},
		{"/.aws/", "AWS Directory", scanner.SeverityCritical},
		{"/.ssh/", "SSH Directory", scanner.SeverityCritical},
		{"/.docker/", "Docker Directory", scanner.SeverityHigh},
		{"/.kube/", "Kubernetes Directory", scanner.SeverityHigh},
		{"/.npm/", "NPM Directory", scanner.SeverityMedium},
		{"/.composer/", "Composer Directory", scanner.SeverityMedium},
		{"/node_modules/", "Node Modules", scanner.SeverityMedium},
		{"/vendor/", "Vendor Directory", scanner.SeverityMedium},
		{"/bower_components/", "Bower Components", scanner.SeverityMedium},
		{"/.idea/", "IntelliJ IDEA Directory", scanner.SeverityMedium},
		{"/.vscode/", "VS Code Directory", scanner.SeverityMedium},
	}

	for _, sd := range sensitiveDirs {
		testURL := baseURL + sd.path

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Check if it's actually a directory listing (not a 404 page)
			if len(body) > 100 && !strings.Contains(bodyStr, "404") && !strings.Contains(bodyStr, "Not Found") {
				vuln := scanner.Vulnerability{
					Type:        "SENSITIVE_DIRECTORY",
					Severity:    sd.severity,
					URL:         testURL,
					Description: sd.name + " is accessible",
					Evidence:    "Directory accessible",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	// Check for backup files
	backupExtensions := []string{".bak", ".old", ".backup", ".orig", ".save", ".swp", ".swo", "~"}
	backupPaths := []string{
		"/index",
		"/config",
		"/database",
		"/db",
		"/admin",
		"/login",
		"/wp-config",
		"/.env",
		"/settings",
		"/application",
	}

	for _, path := range backupPaths {
		for _, ext := range backupExtensions {
			testURL := baseURL + path + ext

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				if len(body) > 0 {
					vuln := scanner.Vulnerability{
						Type:        "BACKUP_FILE",
						Severity:    scanner.SeverityHigh,
						URL:         testURL,
						Description: "Backup file exposed",
						Evidence:    "File accessible",
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}
