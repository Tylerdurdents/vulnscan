package crawler

import (
	"testing"
	"time"
)

func TestNewCrawler(t *testing.T) {
	config := CrawlerConfig{
		MaxDepth:  3,
		MaxPages:  100,
		Threads:   5,
		Timeout:   30 * time.Second,
		UserAgent: "TestAgent",
		SameDomain: true,
	}

	c := NewCrawler(config)
	if c == nil {
		t.Fatal("Failed to create crawler")
	}

	if c.config.MaxDepth != 3 {
		t.Errorf("Expected MaxDepth 3, got %d", c.config.MaxDepth)
	}

	if c.config.MaxPages != 100 {
		t.Errorf("Expected MaxPages 100, got %d", c.config.MaxPages)
	}
}

func TestNewCrawlerDefaults(t *testing.T) {
	config := CrawlerConfig{}
	c := NewCrawler(config)

	if c.config.MaxDepth != 3 {
		t.Errorf("Expected default MaxDepth 3, got %d", c.config.MaxDepth)
	}

	if c.config.MaxPages != 100 {
		t.Errorf("Expected default MaxPages 100, got %d", c.config.MaxPages)
	}

	if c.config.Threads != 5 {
		t.Errorf("Expected default Threads 5, got %d", c.config.Threads)
	}
}

func TestExtractLinks(t *testing.T) {
	c := NewCrawler(CrawlerConfig{})

	html := `<html>
<a href="https://example.com/page1">Link 1</a>
<a href="/page2">Link 2</a>
<img src="https://example.com/image.png">
<form action="https://example.com/submit">
</html>`

	links := c.extractLinks(html, "https://example.com")

	if len(links) < 2 {
		t.Errorf("Expected at least 2 links, got %d", len(links))
	}
}

func TestExtractForms(t *testing.T) {
	c := NewCrawler(CrawlerConfig{})

	html := `<html>
<form action="/submit" method="post">
<input name="username" type="text">
<input name="password" type="password">
</form>
</html>`

	forms := c.extractForms(html, "https://example.com")

	if len(forms) != 1 {
		t.Fatalf("Expected 1 form, got %d", len(forms))
	}

	if forms[0].Method != "POST" {
		t.Errorf("Expected POST method, got %s", forms[0].Method)
	}

	if len(forms[0].Inputs) != 2 {
		t.Errorf("Expected 2 inputs, got %d", len(forms[0].Inputs))
	}
}

func TestShouldCrawl(t *testing.T) {
	c := NewCrawler(CrawlerConfig{SameDomain: true})
	c.baseHost = "example.com"

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/page", true},
		{"https://other.com/page", false},
		{"http://example.com/page", true},
		{"ftp://example.com/file", false},
	}

	for _, tt := range tests {
		result := c.shouldCrawl(tt.url)
		if result != tt.expected {
			t.Errorf("shouldCrawl(%s) = %v, expected %v", tt.url, result, tt.expected)
		}
	}
}
