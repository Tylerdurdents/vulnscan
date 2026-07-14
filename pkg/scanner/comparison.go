package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/eonedge/vulnscan/pkg/utils"
)

// ScanComparison represents a comparison between two scans
type ScanComparison struct {
	Target          string                `json:"target"`
	Scan1           ScanResult            `json:"scan1"`
	Scan2           ScanResult            `json:"scan2"`
	NewVulns        []Vulnerability       `json:"new_vulnerabilities"`
	FixedVulns      []Vulnerability       `json:"fixed_vulnerabilities"`
	UnchangedVulns  []Vulnerability       `json:"unchanged_vulnerabilities"`
	Summary         ComparisonSummary     `json:"summary"`
}

// ComparisonSummary holds summary of comparison
type ComparisonSummary struct {
	TotalScan1      int `json:"total_scan1"`
	TotalScan2      int `json:"total_scan2"`
	New             int `json:"new"`
	Fixed           int `json:"fixed"`
	Unchanged       int `json:"unchanged"`
	Scan1Time       time.Time `json:"scan1_time"`
	Scan2Time       time.Time `json:"scan2_time"`
}

// CompareScans compares two scan results
func CompareScans(scan1, scan2 *ScanResult) *ScanComparison {
	comparison := &ScanComparison{
		Target: scan1.Target,
		Scan1:  *scan1,
		Scan2:  *scan2,
	}

	// Create maps for quick lookup
	scan1Map := make(map[string]bool)
	scan2Map := make(map[string]bool)

	for _, vuln := range scan1.Vulnerabilities {
		key := getVulnKey(vuln)
		scan1Map[key] = true
	}

	for _, vuln := range scan2.Vulnerabilities {
		key := getVulnKey(vuln)
		scan2Map[key] = true
	}

	// Find new vulnerabilities (in scan2 but not in scan1)
	for _, vuln := range scan2.Vulnerabilities {
		key := getVulnKey(vuln)
		if !scan1Map[key] {
			comparison.NewVulns = append(comparison.NewVulns, vuln)
		}
	}

	// Find fixed vulnerabilities (in scan1 but not in scan2)
	for _, vuln := range scan1.Vulnerabilities {
		key := getVulnKey(vuln)
		if !scan2Map[key] {
			comparison.FixedVulns = append(comparison.FixedVulns, vuln)
		}
	}

	// Find unchanged vulnerabilities (in both scans)
	for _, vuln := range scan2.Vulnerabilities {
		key := getVulnKey(vuln)
		if scan1Map[key] {
			comparison.UnchangedVulns = append(comparison.UnchangedVulns, vuln)
		}
	}

	// Create summary
	comparison.Summary = ComparisonSummary{
		TotalScan1: len(scan1.Vulnerabilities),
		TotalScan2: len(scan2.Vulnerabilities),
		New:        len(comparison.NewVulns),
		Fixed:      len(comparison.FixedVulns),
		Unchanged:  len(comparison.UnchangedVulns),
		Scan1Time:  scan1.StartTime,
		Scan2Time:  scan2.StartTime,
	}

	return comparison
}

// getVulnKey creates a unique key for a vulnerability
func getVulnKey(vuln Vulnerability) string {
	return fmt.Sprintf("%s:%s:%s:%s", vuln.Type, vuln.URL, vuln.Parameter, vuln.Payload)
}

// LoadScanResult loads a scan result from a JSON file
func LoadScanResult(filePath string) (*ScanResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan result: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}

	return &result, nil
}

// SaveComparison saves a comparison to a JSON file
func SaveComparison(comparison *ScanComparison, filePath string) error {
	data, err := json.MarshalIndent(comparison, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal comparison: %w", err)
	}

	return os.WriteFile(filePath, data, 0644)
}

// PrintComparison prints a comparison to the console
func PrintComparison(comparison *ScanComparison) {
	logger := utils.NewLogger(utils.INFO, "COMPARE")

	logger.Info("Scan Comparison: %s", comparison.Target)
	logger.Info("Scan 1: %s (%d vulnerabilities)", comparison.Summary.Scan1Time.Format("2006-01-02 15:04:05"), comparison.Summary.TotalScan1)
	logger.Info("Scan 2: %s (%d vulnerabilities)", comparison.Summary.Scan2Time.Format("2006-01-02 15:04:05"), comparison.Summary.TotalScan2)

	fmt.Println()
	fmt.Printf("  New vulnerabilities:     %d\n", comparison.Summary.New)
	fmt.Printf("  Fixed vulnerabilities:   %d\n", comparison.Summary.Fixed)
	fmt.Printf("  Unchanged vulnerabilities: %d\n", comparison.Summary.Unchanged)

	if len(comparison.NewVulns) > 0 {
		fmt.Println("\n  New vulnerabilities:")
		for _, vuln := range comparison.NewVulns {
			fmt.Printf("    [+] %s - %s (%s)\n", vuln.Type, vuln.Severity, vuln.URL)
		}
	}

	if len(comparison.FixedVulns) > 0 {
		fmt.Println("\n  Fixed vulnerabilities:")
		for _, vuln := range comparison.FixedVulns {
			fmt.Printf("    [-] %s - %s (%s)\n", vuln.Type, vuln.Severity, vuln.URL)
		}
	}
}
