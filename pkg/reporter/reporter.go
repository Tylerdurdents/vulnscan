package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/eonedge/vulnscan/pkg/scanner"
)

// ReportFormat represents the output format of the report
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatCSV  ReportFormat = "csv"
	FormatHTML ReportFormat = "html"
)

// Reporter handles report generation
type Reporter struct {
	format ReportFormat
	output string
}

// NewReporter creates a new reporter instance
func NewReporter(format ReportFormat, output string) *Reporter {
	return &Reporter{
		format: format,
		output: output,
	}
}

// Generate generates a report from scan results
func (r *Reporter) Generate(result *scanner.ScanResult) error {
	switch r.format {
	case FormatJSON:
		return r.generateJSON(result)
	case FormatCSV:
		return r.generateCSV(result)
	case FormatHTML:
		return r.generateHTML(result)
	default:
		return fmt.Errorf("unsupported format: %s", r.format)
	}
}

// generateJSON generates a JSON report
func (r *Reporter) generateJSON(result *scanner.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(r.output, data, 0644)
}

// generateCSV generates a CSV report
func (r *Reporter) generateCSV(result *scanner.ScanResult) error {
	file, err := os.Create(r.output)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Type", "Severity", "URL", "Parameter", "Payload", "Description", "Evidence", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		record := []string{
			vuln.Type,
			string(vuln.Severity),
			vuln.URL,
			vuln.Parameter,
			vuln.Payload,
			vuln.Description,
			vuln.Evidence,
			vuln.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	return nil
}

// generateHTML generates an HTML report
func (r *Reporter) generateHTML(result *scanner.ScanResult) error {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScan Report - {{.Target}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #666; }
        .summary-card .value { font-size: 24px; font-weight: bold; color: #007bff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .footer { margin-top: 20px; text-align: center; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VulnScan Security Report</h1>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value">{{.Target}}</div>
            </div>
            <div class="summary-card">
                <h3>Endpoints Scanned</h3>
                <div class="value">{{.Endpoints}}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities Found</h3>
                <div class="value">{{len .Vulnerabilities}}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{{.Duration}}</div>
            </div>
        </div>

        {{if .Vulnerabilities}}
        <h2>Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {{range .Vulnerabilities}}
                <tr>
                    <td>{{.Type}}</td>
                    <td class="severity-{{.Severity | lower}}">{{.Severity}}</td>
                    <td>{{.URL}}</td>
                    <td>{{.Parameter}}</td>
                    <td>{{.Description}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <p>No vulnerabilities found.</p>
        {{end}}

        <div class="footer">
            <p>Report generated on {{.EndTime.Format "2006-01-02 15:04:05"}} by VulnScan</p>
        </div>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"lower": func(s interface{}) string {
			return strings.ToLower(fmt.Sprintf("%v", s))
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Create output directory if it doesn't exist
	dir := filepath.Dir(r.output)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(r.output)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	return tmpl.Execute(file, result)
}
