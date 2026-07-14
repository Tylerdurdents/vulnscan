package scanner

import (
	"os"
	"testing"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/utils"
)

func TestNewScanner(t *testing.T) {
	config := ScannerConfig{
		Threads:   10,
		Timeout:   30 * time.Second,
		UserAgent: "TestAgent",
		Modules:   []string{"sqli", "xss"},
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	if s.config.Threads != 10 {
		t.Errorf("Expected Threads 10, got %d", s.config.Threads)
	}
}

func TestNewScannerDefaults(t *testing.T) {
	config := ScannerConfig{}
	s := NewScanner(config)

	if s.config.Threads != 10 {
		t.Errorf("Expected default Threads 10, got %d", s.config.Threads)
	}

	if s.config.Timeout != 30*time.Second {
		t.Errorf("Expected default Timeout 30s, got %v", s.config.Timeout)
	}

	if s.config.UserAgent != "VulnScan/1.0" {
		t.Errorf("Expected default UserAgent 'VulnScan/1.0', got '%s'", s.config.UserAgent)
	}
}

func TestRegisterModule(t *testing.T) {
	s := NewScanner(ScannerConfig{})

	module := &mockModule{name: "test", desc: "Test module"}
	s.RegisterModule(module)

	if len(s.modules) != 1 {
		t.Errorf("Expected 1 module, got %d", len(s.modules))
	}

	if s.modules["test"] == nil {
		t.Error("Module 'test' not registered")
	}
}

func TestGetActiveModules(t *testing.T) {
	s := NewScanner(ScannerConfig{Modules: []string{"sqli", "xss"}})

	s.RegisterModule(&mockModule{name: "sqli", desc: "SQLi"})
	s.RegisterModule(&mockModule{name: "xss", desc: "XSS"})
	s.RegisterModule(&mockModule{name: "cmdi", desc: "CMDI"})

	active := s.getActiveModules()
	if len(active) != 2 {
		t.Errorf("Expected 2 active modules, got %d", len(active))
	}
}

func TestGetAllActiveModules(t *testing.T) {
	s := NewScanner(ScannerConfig{})

	s.RegisterModule(&mockModule{name: "sqli", desc: "SQLi"})
	s.RegisterModule(&mockModule{name: "xss", desc: "XSS"})

	active := s.getActiveModules()
	if len(active) != 2 {
		t.Errorf("Expected 2 active modules, got %d", len(active))
	}
}

func TestSaveLoadScanState(t *testing.T) {
	state := &ScanState{
		Target:    "https://example.com",
		StartTime: time.Now(),
		CompletedParams: map[string]bool{
			"https://example.com:GET": true,
		},
	}

	tmpFile := "/tmp/test_scan_state.json"
	defer os.Remove(tmpFile)

	// Save state
	err := SaveScanState(state, tmpFile)
	if err != nil {
		t.Fatalf("SaveScanState error: %v", err)
	}

	// Load state
	loaded, err := LoadScanState(tmpFile)
	if err != nil {
		t.Fatalf("LoadScanState error: %v", err)
	}

	if loaded.Target != state.Target {
		t.Errorf("Expected target '%s', got '%s'", state.Target, loaded.Target)
	}

	if !loaded.CompletedParams["https://example.com:GET"] {
		t.Error("Expected completed param to be true")
	}
}

func TestLoadScanStateNotFound(t *testing.T) {
	_, err := LoadScanState("/nonexistent/file.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

type mockModule struct {
	name string
	desc string
}

func (m *mockModule) Name() string        { return m.name }
func (m *mockModule) Description() string  { return m.desc }
func (m *mockModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []Vulnerability {
	return nil
}
