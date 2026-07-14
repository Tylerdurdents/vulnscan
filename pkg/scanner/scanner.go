package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Vulnerability represents a discovered vulnerability
type Vulnerability struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// ScanResult holds the results of a scan
type ScanResult struct {
	Target         string          `json:"target"`
	Endpoints      int             `json:"endpoints"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	StartTime      time.Time       `json:"start_time"`
	EndTime        time.Time       `json:"end_time"`
	Duration       time.Duration   `json:"duration"`
}

// Module defines the interface for vulnerability scanning modules
type Module interface {
	Name() string
	Description() string
	Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []Vulnerability
}

// ScannerConfig holds configuration for the scanner
type ScannerConfig struct {
	Threads   int
	Timeout   time.Duration
	UserAgent string
	Modules   []string
}

// Scanner handles vulnerability scanning operations
type Scanner struct {
	config  ScannerConfig
	client  *utils.HTTPClient
	modules map[string]Module
	logger  *utils.Logger
	mu      sync.Mutex
}

// NewScanner creates a new scanner instance
func NewScanner(config ScannerConfig) *Scanner {
	if config.Threads == 0 {
		config.Threads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "VulnScan/1.0"
	}

	client := utils.NewHTTPClient(config.Timeout, true)
	client.SetUserAgent(config.UserAgent)

	return &Scanner{
		config:  config,
		client:  client,
		modules: make(map[string]Module),
		logger:  utils.NewLogger(utils.INFO, "SCANNER"),
	}
}

// RegisterModule registers a vulnerability scanning module
func (s *Scanner) RegisterModule(module Module) {
	s.modules[module.Name()] = module
	s.logger.Debug("Registered module: %s", module.Name())
}

// Scan scans endpoints for vulnerabilities
func (s *Scanner) Scan(endpoints []crawler.Endpoint) (*ScanResult, error) {
	result := &ScanResult{
		StartTime:       time.Now(),
		Vulnerabilities: []Vulnerability{},
	}

	s.logger.Info("Starting scan on %d endpoints with %d modules", len(endpoints), len(s.modules))

	// Filter modules based on config
	activeModules := s.getActiveModules()
	if len(activeModules) == 0 {
		return nil, fmt.Errorf("no active modules selected")
	}

	s.logger.Info("Active modules: %v", getModuleNames(activeModules))

	// Create work queue
	workChan := make(chan crawler.Endpoint, len(endpoints))
	resultChan := make(chan []Vulnerability, len(endpoints))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go s.worker(&wg, workChan, resultChan, activeModules)
	}

	// Send work
	for _, endpoint := range endpoints {
		workChan <- endpoint
	}
	close(workChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for vulns := range resultChan {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Endpoints = len(endpoints)

	s.logger.Info("Scan completed. Found %d vulnerabilities in %v", len(result.Vulnerabilities), result.Duration)
	return result, nil
}

// worker processes endpoints from the work queue
func (s *Scanner) worker(wg *sync.WaitGroup, workChan <-chan crawler.Endpoint, resultChan chan<- []Vulnerability, modules []Module) {
	defer wg.Done()

	for endpoint := range workChan {
		for _, module := range modules {
			vulns := module.Scan(s.client, endpoint)
			if len(vulns) > 0 {
				resultChan <- vulns
			}
		}
	}
}

// getActiveModules returns the modules that should be used for scanning
func (s *Scanner) getActiveModules() []Module {
	var active []Module

	if len(s.config.Modules) == 0 {
		// Use all modules if none specified
		for _, module := range s.modules {
			active = append(active, module)
		}
		return active
	}

	for _, name := range s.config.Modules {
		if module, ok := s.modules[name]; ok {
			active = append(active, module)
		}
	}

	return active
}

// getModuleNames returns the names of the modules
func getModuleNames(modules []Module) []string {
	names := make([]string, len(modules))
	for i, module := range modules {
		names[i] = module.Name()
	}
	return names
}
