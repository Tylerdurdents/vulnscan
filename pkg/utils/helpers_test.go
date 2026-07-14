package utils

import (
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"example.com", "https://example.com", false},
		{"http://example.com", "http://example.com", false},
		{"https://example.com", "https://example.com", false},
		{"https://example.com/path", "https://example.com/path", false},
	}

	for _, tt := range tests {
		result, err := NormalizeURL(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeURL(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if result != tt.expected {
			t.Errorf("NormalizeURL(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestGetBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path", "https://example.com"},
		{"http://example.com:8080/path", "http://example.com:8080"},
		{"https://example.com", "https://example.com"},
	}

	for _, tt := range tests {
		result, err := GetBaseURL(tt.input)
		if err != nil {
			t.Errorf("GetBaseURL(%s) error: %v", tt.input, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("GetBaseURL(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestIsSameDomain(t *testing.T) {
	tests := []struct {
		url1     string
		url2     string
		expected bool
	}{
		{"https://example.com/a", "https://example.com/b", true},
		{"https://example.com", "https://other.com", false},
		{"https://example.com", "http://example.com", true},
	}

	for _, tt := range tests {
		result := IsSameDomain(tt.url1, tt.url2)
		if result != tt.expected {
			t.Errorf("IsSameDomain(%s, %s) = %v, expected %v", tt.url1, tt.url2, result, tt.expected)
		}
	}
}

func TestExtractParams(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"https://example.com?page=1&sort=name", 2},
		{"https://example.com", 0},
		{"https://example.com?key=value", 1},
	}

	for _, tt := range tests {
		result := ExtractParams(tt.input)
		if len(result) != tt.expected {
			t.Errorf("ExtractParams(%s) returned %d params, expected %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestInjectParam(t *testing.T) {
	result, err := InjectParam("https://example.com?page=1", "page", "2")
	if err != nil {
		t.Fatalf("InjectParam error: %v", err)
	}
	if result != "https://example.com?page=2" {
		t.Errorf("InjectParam = %s, expected https://example.com?page=2", result)
	}
}

func TestContainsPattern(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
		want    bool
	}{
		{"Hello World", "Hello", true},
		{"Hello World", "hello", false},
		{"Hello World", "(?i)hello", true},
		{"test123", "\\d+", true},
	}

	for _, tt := range tests {
		result := ContainsPattern(tt.input, tt.pattern)
		if result != tt.want {
			t.Errorf("ContainsPattern(%s, %s) = %v, expected %v", tt.input, tt.pattern, result, tt.want)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	result := UniqueStrings(input)
	if len(result) != 3 {
		t.Errorf("UniqueStrings returned %d items, expected 3", len(result))
	}
}

func TestJoinURL(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://example.com", "path", "https://example.com/path"},
		{"https://example.com/", "path", "https://example.com/path"},
		{"https://example.com", "/path", "https://example.com/path"},
	}

	for _, tt := range tests {
		result := JoinURL(tt.base, tt.path)
		if result != tt.expected {
			t.Errorf("JoinURL(%s, %s) = %s, expected %s", tt.base, tt.path, result, tt.expected)
		}
	}
}

func TestExtractContext(t *testing.T) {
	body := "This is a test body with some content"
	result := ExtractContext(body, "test")
	if result == "" {
		t.Error("ExtractContext returned empty string")
	}
}

func TestCompileRegex(t *testing.T) {
	re, err := CompileRegex("(?i)test")
	if err != nil {
		t.Fatalf("CompileRegex error: %v", err)
	}
	if !re.MatchString("Test") {
		t.Error("Regex should match 'Test'")
	}
}

func TestGetCurrentTime(t *testing.T) {
	before := time.Now()
	result := GetCurrentTime()
	after := time.Now()

	if result.Before(before) || result.After(after) {
		t.Errorf("GetCurrentTime() = %v, not between %v and %v", result, before, after)
	}
}
