package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Scanner settings
	Scanner ScannerConfig `yaml:"scanner"`

	// Crawler settings
	Crawler CrawlerConfig `yaml:"crawler"`

	// Output settings
	Output OutputConfig `yaml:"output"`

	// Authentication settings
	Auth AuthConfig `yaml:"auth"`

	// Rate limiting settings
	RateLimit RateLimitConfig `yaml:"rate_limit"`

	// Modules to use
	Modules []string `yaml:"modules"`

	// Custom payloads file
	Payloads string `yaml:"payloads"`

	// Database settings
	Database DatabaseConfig `yaml:"database"`

	// Notification settings
	Notification NotificationConfig `yaml:"notification"`
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	Threads int    `yaml:"threads"`
	Timeout string `yaml:"timeout"`
	Profile string `yaml:"profile"` // quick, full, stealth
}

// CrawlerConfig holds crawler configuration
type CrawlerConfig struct {
	MaxDepth   int  `yaml:"max_depth"`
	MaxPages   int  `yaml:"max_pages"`
	SameDomain bool `yaml:"same_domain"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	Format string `yaml:"format"` // json, csv, html, pdf
	File   string `yaml:"file"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Type   string `yaml:"type"`   // cookie, bearer, basic, header
	Value  string `yaml:"value"`
	Header string `yaml:"header"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	RPS     int  `yaml:"rps"` // requests per second
	Burst   int  `yaml:"burst"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Type     string            `yaml:"type"` // email, slack, webhook
	Settings map[string]string `yaml:"settings"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Scanner: ScannerConfig{
			Threads: 10,
			Timeout: "30s",
			Profile: "full",
		},
		Crawler: CrawlerConfig{
			MaxDepth:   3,
			MaxPages:   100,
			SameDomain: true,
		},
		Output: OutputConfig{
			Format: "json",
			File:   "report.json",
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			RPS:     10,
			Burst:   20,
		},
		Modules: []string{"sqli", "xss"},
		Database: DatabaseConfig{
			Enabled: false,
			Path:    "vulnscan.db",
		},
		Notification: NotificationConfig{
			Enabled: false,
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// GetTimeout returns the timeout as time.Duration
func (c *ScannerConfig) GetTimeout() time.Duration {
	duration, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return duration
}

// GetScanProfile returns the scan profile configuration
func GetScanProfile(profile string) map[string]interface{} {
	profiles := map[string]map[string]interface{}{
		"quick": {
			"threads":   20,
			"max_depth": 1,
			"max_pages": 10,
			"rate_limit": 0,
			"modules":   []string{"sqli", "xss"},
		},
		"full": {
			"threads":   10,
			"max_depth": 3,
			"max_pages": 100,
			"rate_limit": 0,
			"modules":   []string{"sqli", "xss", "cmdi", "csrf", "lfi", "openredirect", "ssrf", "ssti", "xxe", "jwt", "cors", "headers"},
		},
		"stealth": {
			"threads":   2,
			"max_depth": 2,
			"max_pages": 50,
			"rate_limit": 5,
			"modules":   []string{"sqli", "xss", "lfi"},
		},
	}

	if p, exists := profiles[profile]; exists {
		return p
	}

	return profiles["full"]
}
