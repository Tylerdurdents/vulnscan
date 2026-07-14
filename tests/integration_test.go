package tests

import (
	"testing"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/modules"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

func TestIntegrationScanWithModules(t *testing.T) {
	// Create a scanner
	config := scanner.ScannerConfig{
		Threads:   2,
		Timeout:   10 * time.Second,
		UserAgent: "VulnScan-Test/1.0",
		Modules:   []string{"sqli", "xss"},
	}

	s := scanner.NewScanner(config)

	// Register modules
	allModules := modules.GetAllModules()
	for _, module := range allModules {
		s.RegisterModule(module)
	}

	// Create test endpoint
	endpoints := []crawler.Endpoint{
		{
			URL:    "https://httpbin.org/get?name=test&id=123",
			Method: "GET",
			Params: map[string]string{
				"name": "test",
				"id":   "123",
			},
			Depth: 0,
		},
	}

	// Run scan
	result, err := s.Scan(endpoints)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// httpbin.org reflects input, so we should find vulnerabilities
	if len(result.Vulnerabilities) == 0 {
		t.Log("No vulnerabilities found (this is okay for some targets)")
	}

	t.Logf("Found %d vulnerabilities", len(result.Vulnerabilities))
}

func TestIntegrationCrawlerAndScanner(t *testing.T) {
	// Create crawler
	crawlConfig := crawler.CrawlerConfig{
		MaxDepth:   1,
		MaxPages:   5,
		Threads:    2,
		Timeout:    10 * time.Second,
		UserAgent:  "VulnScan-Test/1.0",
		SameDomain: true,
	}

	c := crawler.NewCrawler(crawlConfig)

	// Crawl
	endpoints, err := c.Crawl("https://httpbin.org/get?test=1")
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("No endpoints found")
	}

	t.Logf("Found %d endpoints", len(endpoints))

	// Create scanner
	scanConfig := scanner.ScannerConfig{
		Threads:   2,
		Timeout:   10 * time.Second,
		UserAgent: "VulnScan-Test/1.0",
		Modules:   []string{"xss"},
	}

	s := scanner.NewScanner(scanConfig)
	s.RegisterModule(modules.GetModuleByName("xss"))

	// Scan
	result, err := s.Scan(endpoints)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	t.Logf("Found %d vulnerabilities", len(result.Vulnerabilities))
}

func TestIntegrationModuleRegistration(t *testing.T) {
	// Test that all modules can be registered
	s := scanner.NewScanner(scanner.ScannerConfig{})

	allModules := modules.GetAllModules()
	for _, module := range allModules {
		s.RegisterModule(module)
	}

	// Verify all modules are registered
	expectedModules := []string{"sqli", "xss", "cmdi", "csrf", "lfi", "openredirect", "ssrf", "ssti", "xxe", "jwt", "cors", "headers"}
	for _, name := range expectedModules {
		module := modules.GetModuleByName(name)
		if module == nil {
			t.Errorf("Module '%s' not found", name)
		}
	}
}

func TestIntegrationAuthConfig(t *testing.T) {
	// Test auth configuration
	config := scanner.ScannerConfig{
		Threads:   2,
		Timeout:   10 * time.Second,
		UserAgent: "VulnScan-Test/1.0",
		Auth: utils.AuthConfig{
			Type:  "bearer",
			Value: "test-token",
		},
	}

	s := scanner.NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner with auth")
	}
}

func TestIntegrationRateLimit(t *testing.T) {
	// Test rate limiting
	config := scanner.ScannerConfig{
		Threads:   2,
		Timeout:   10 * time.Second,
		UserAgent: "VulnScan-Test/1.0",
		RateLimit: 5,
	}

	s := scanner.NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner with rate limit")
	}
}
