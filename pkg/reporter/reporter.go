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

	"github.com/jung-kurt/gofpdf"
	"github.com/eonedge/vulnscan/pkg/scanner"
)

// ReportFormat represents the output format of the report
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatCSV  ReportFormat = "csv"
	FormatHTML ReportFormat = "html"
	FormatPDF  ReportFormat = "pdf"
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
	case FormatPDF:
		return r.generatePDF(result)
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

// generatePDF generates a PDF report
func (r *Reporter) generatePDF(result *scanner.ScanResult) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 10)

	// Add title page
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 24)
	pdf.Cell(0, 20, "VulnScan Security Report")
	pdf.Ln(30)

	// Summary section
	pdf.SetFont("Helvetica", "B", 16)
	pdf.Cell(0, 10, "Scan Summary")
	pdf.Ln(15)

	pdf.SetFont("Helvetica", "", 12)
	pdf.Cell(0, 8, fmt.Sprintf("Target: %s", result.Target))
	pdf.Ln(8)
	pdf.Cell(0, 8, fmt.Sprintf("Endpoints scanned: %d", result.Endpoints))
	pdf.Ln(8)
	pdf.Cell(0, 8, fmt.Sprintf("Vulnerabilities found: %d", len(result.Vulnerabilities)))
	pdf.Ln(8)
	pdf.Cell(0, 8, fmt.Sprintf("Duration: %v", result.Duration))
	pdf.Ln(8)
	pdf.Cell(0, 8, fmt.Sprintf("Date: %s", result.StartTime.Format("2006-01-02 15:04:05")))
	pdf.Ln(20)

	// Vulnerabilities section
	if len(result.Vulnerabilities) > 0 {
		pdf.SetFont("Helvetica", "B", 16)
		pdf.Cell(0, 10, "Vulnerabilities")
		pdf.Ln(15)

		// Table header
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetFillColor(200, 200, 200)
		pdf.Cell(30, 8, "Type")
		pdf.Cell(20, 8, "Severity")
		pdf.Cell(80, 8, "URL")
		pdf.Cell(60, 8, "Description")
		pdf.Ln(8)

		// Table rows
		pdf.SetFont("Helvetica", "", 9)
		for _, vuln := range result.Vulnerabilities {
			// Check if we need a new page
			if pdf.GetY() > 270 {
				pdf.AddPage()
				pdf.SetFont("Helvetica", "B", 10)
				pdf.SetFillColor(200, 200, 200)
				pdf.Cell(30, 8, "Type")
				pdf.Cell(20, 8, "Severity")
				pdf.Cell(80, 8, "URL")
				pdf.Cell(60, 8, "Description")
				pdf.Ln(8)
				pdf.SetFont("Helvetica", "", 9)
			}

			// Set color based on severity
			switch vuln.Severity {
			case scanner.SeverityCritical:
				pdf.SetTextColor(220, 53, 69)
			case scanner.SeverityHigh:
				pdf.SetTextColor(253, 126, 20)
			case scanner.SeverityMedium:
				pdf.SetTextColor(255, 193, 7)
			case scanner.SeverityLow:
				pdf.SetTextColor(40, 167, 69)
			default:
				pdf.SetTextColor(0, 0, 0)
			}

			pdf.Cell(30, 7, truncateString(string(vuln.Type), 15))
			pdf.Cell(20, 7, string(vuln.Severity))
			pdf.Cell(80, 7, truncateString(vuln.URL, 40))
			pdf.Cell(60, 7, truncateString(vuln.Description, 30))
			pdf.Ln(7)
		}

		// Reset text color
		pdf.SetTextColor(0, 0, 0)
	}

	// Create output directory if it doesn't exist
	dir := filepath.Dir(r.output)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return pdf.OutputFileAndClose(r.output)
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
