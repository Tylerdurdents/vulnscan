package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
)

// ScanState represents the state of a scan for resume capability
type ScanState struct {
	Target          string                 `json:"target"`
	StartTime       time.Time              `json:"start_time"`
	Endpoints       []crawler.Endpoint     `json:"endpoints"`
	CompletedParams map[string]bool        `json:"completed_params"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	LastIndex       int                    `json:"last_index"`
	Modules         []string               `json:"modules"`
}

// SaveScanState saves the current scan state to a file
func SaveScanState(state *ScanState, filePath string) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan state: %w", err)
	}

	return os.WriteFile(filePath, data, 0644)
}

// LoadScanState loads a scan state from a file
func LoadScanState(filePath string) (*ScanState, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan state: %w", err)
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan state: %w", err)
	}

	return &state, nil
}

// GetStateKey returns a unique key for an endpoint and parameter
func GetStateKey(endpoint crawler.Endpoint, param string) string {
	return fmt.Sprintf("%s:%s:%s", endpoint.URL, endpoint.Method, param)
}
