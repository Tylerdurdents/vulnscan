package tests

import (
	"testing"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/modules"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

func BenchmarkNewHTTPClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		utils.NewHTTPClient(30*time.Second, true)
	}
}

func BenchmarkNormalizeURL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		utils.NormalizeURL("https://example.com/path?query=value")
	}
}

func BenchmarkExtractParams(b *testing.B) {
	url := "https://example.com?a=1&b=2&c=3&d=4&e=5"
	for i := 0; i < b.N; i++ {
		utils.ExtractParams(url)
	}
}

func BenchmarkContainsPattern(b *testing.B) {
	body := "This is a test string with some content to search through"
	pattern := "(?i)test"
	for i := 0; i < b.N; i++ {
		utils.ContainsPattern(body, pattern)
	}
}

func BenchmarkNewCrawler(b *testing.B) {
	config := crawler.CrawlerConfig{
		MaxDepth: 3,
		MaxPages: 100,
		Threads:  5,
		Timeout:  30 * time.Second,
	}
	for i := 0; i < b.N; i++ {
		crawler.NewCrawler(config)
	}
}

func BenchmarkNewScanner(b *testing.B) {
	config := scanner.ScannerConfig{
		Threads:   10,
		Timeout:   30 * time.Second,
		UserAgent: "VulnScan/1.0",
	}
	for i := 0; i < b.N; i++ {
		scanner.NewScanner(config)
	}
}

func BenchmarkGetAllModules(b *testing.B) {
	for i := 0; i < b.N; i++ {
		modules.GetAllModules()
	}
}

func BenchmarkGetModuleByName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		modules.GetModuleByName("sqli")
	}
}

func BenchmarkRateLimiter(b *testing.B) {
	limiter := utils.NewRateLimiter(1000, 2000)
	for i := 0; i < b.N; i++ {
		limiter.Wait()
	}
}
