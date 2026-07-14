package tests

import (
	"testing"
	"time"

	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/modules"
)

func TestScannerConfig(t *testing.T) {
	config := scanner.ScannerConfig{
		Threads:   10,
		Timeout:   30 * time.Second,
		UserAgent: "TestAgent",
		Modules:   []string{"sqli", "xss"},
	}

	s := scanner.NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}
}

func TestGetAllModules(t *testing.T) {
	allModules := modules.GetAllModules()
	if len(allModules) == 0 {
		t.Fatal("No modules returned")
	}

	expectedModules := []string{"sqli", "xss", "cmdi", "csrf", "lfi", "openredirect", "ssrf", "ssti", "xxe", "jwt"}
	if len(allModules) != len(expectedModules) {
		t.Errorf("Expected %d modules, got %d", len(expectedModules), len(allModules))
	}
}

func TestGetModuleByName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"sqli", true},
		{"xss", true},
		{"nonexistent", false},
	}

	for _, test := range tests {
		module := modules.GetModuleByName(test.name)
		if test.expected && module == nil {
			t.Errorf("Expected module %s, got nil", test.name)
		}
		if !test.expected && module != nil {
			t.Errorf("Expected nil for module %s, got %v", test.name, module)
		}
	}
}
