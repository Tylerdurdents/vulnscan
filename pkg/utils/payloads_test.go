package utils

import (
	"os"
	"testing"
)

func TestLoadPayloadsFromFile(t *testing.T) {
	// Create a temporary test file
	content := `# Comment
payload1|pattern1|description1
payload2|pattern2|description2
payload3
`
	tmpFile, err := os.CreateTemp("", "payloads-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	payloads, err := LoadPayloadsFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPayloadsFromFile error: %v", err)
	}

	if len(payloads) != 3 {
		t.Errorf("Expected 3 payloads, got %d", len(payloads))
	}

	// Check first payload
	if payloads[0].Value != "payload1" {
		t.Errorf("Expected 'payload1', got '%s'", payloads[0].Value)
	}
	if payloads[0].Pattern != "pattern1" {
		t.Errorf("Expected 'pattern1', got '%s'", payloads[0].Pattern)
	}
	if payloads[0].Description != "description1" {
		t.Errorf("Expected 'description1', got '%s'", payloads[0].Description)
	}

	// Check third payload (no pattern/description)
	if payloads[2].Value != "payload3" {
		t.Errorf("Expected 'payload3', got '%s'", payloads[2].Value)
	}
	if payloads[2].Pattern != "" {
		t.Errorf("Expected empty pattern, got '%s'", payloads[2].Pattern)
	}
}

func TestLoadPayloadsFromFileNotFound(t *testing.T) {
	_, err := LoadPayloadsFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadStringsFromFile(t *testing.T) {
	content := `# Comment
line1
line2
line3
`
	tmpFile, err := os.CreateTemp("", "strings-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	lines, err := LoadStringsFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadStringsFromFile error: %v", err)
	}

	if len(lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}

	if lines[0] != "line1" {
		t.Errorf("Expected 'line1', got '%s'", lines[0])
	}
}

func TestLoadStringsFromFileNotFound(t *testing.T) {
	_, err := LoadStringsFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
