package tests

import (
	"testing"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/utils"
)

func TestCrawlerConfig(t *testing.T) {
	config := crawler.CrawlerConfig{
		MaxDepth:  3,
		MaxPages:  100,
		Threads:   5,
		Timeout:   30 * time.Second,
		UserAgent: "TestAgent",
		SameDomain: true,
	}

	c := crawler.NewCrawler(config)
	if c == nil {
		t.Fatal("Failed to create crawler")
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	}

	for _, test := range tests {
		result, err := utils.NormalizeURL(test.input)
		if err != nil {
			t.Errorf("NormalizeURL(%s) returned error: %v", test.input, err)
		}
		if result != test.expected {
			t.Errorf("NormalizeURL(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestExtractParams(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]string
	}{
		{
			"http://example.com?page=1&sort=name",
			map[string]string{"page": "1", "sort": "name"},
		},
		{
			"http://example.com",
			map[string]string{},
		},
	}

	for _, test := range tests {
		result := utils.ExtractParams(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("ExtractParams(%s) returned %d params, expected %d", test.input, len(result), len(test.expected))
		}
	}
}
