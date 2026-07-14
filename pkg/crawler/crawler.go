package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/eonedge/vulnscan/pkg/utils"
)

// Endpoint represents a discovered URL endpoint
type Endpoint struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Params     map[string]string `json:"params,omitempty"`
	Forms      []Form            `json:"forms,omitempty"`
	Depth      int               `json:"depth"`
	Source     string            `json:"source"`
}

// Form represents an HTML form found on a page
type Form struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Inputs map[string]string `json:"inputs"`
}

// CrawlerConfig holds configuration for the crawler
type CrawlerConfig struct {
	MaxDepth     int
	MaxPages     int
	Threads      int
	Timeout      time.Duration
	UserAgent    string
	IgnoreRobots bool
	SameDomain   bool
}

// Crawler handles web crawling operations
type Crawler struct {
	config    CrawlerConfig
	client    *utils.HTTPClient
	visited   map[string]bool
	endpoints []Endpoint
	mu        sync.Mutex
	wg        sync.WaitGroup
	baseURL   string
	baseHost  string
	logger    *utils.Logger
}

// NewCrawler creates a new crawler instance
func NewCrawler(config CrawlerConfig) *Crawler {
	if config.MaxDepth == 0 {
		config.MaxDepth = 3
	}
	if config.MaxPages == 0 {
		config.MaxPages = 100
	}
	if config.Threads == 0 {
		config.Threads = 5
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "VulnScan/1.0"
	}

	client := utils.NewHTTPClient(config.Timeout, true)
	client.SetUserAgent(config.UserAgent)

	return &Crawler{
		config:    config,
		client:    client,
		visited:   make(map[string]bool),
		endpoints: []Endpoint{},
		logger:    utils.NewLogger(utils.INFO, "CRAWLER"),
	}
}

// Crawl starts crawling from the target URL
func (c *Crawler) Crawl(targetURL string) ([]Endpoint, error) {
	normalizedURL, err := utils.NormalizeURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	c.baseURL, err = utils.GetBaseURL(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get base URL: %w", err)
	}

	parsed, _ := url.Parse(normalizedURL)
	c.baseHost = parsed.Host

	c.logger.Info("Starting crawl on %s (max depth: %d, max pages: %d)", normalizedURL, c.config.MaxDepth, c.config.MaxPages)

	c.wg.Add(1)
	go c.crawl(normalizedURL, 0, "initial")

	c.wg.Wait()

	c.logger.Info("Crawl completed. Found %d endpoints", len(c.endpoints))
	return c.endpoints, nil
}

// crawl recursively crawls a URL
func (c *Crawler) crawl(targetURL string, depth int, source string) {
	defer c.wg.Done()

	if depth > c.config.MaxDepth {
		return
	}

	c.mu.Lock()
	if c.visited[targetURL] || len(c.visited) >= c.config.MaxPages {
		c.mu.Unlock()
		return
	}
	c.visited[targetURL] = true
	c.mu.Unlock()

	c.logger.Debug("Crawling: %s (depth: %d)", targetURL, depth)

	resp, err := c.client.Get(targetURL)
	if err != nil {
		c.logger.Debug("Failed to fetch %s: %v", targetURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("Non-200 status for %s: %d", targetURL, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug("Failed to read body for %s: %v", targetURL, err)
		return
	}

	bodyStr := string(body)

	// Extract and add current endpoint
	params := utils.ExtractParams(targetURL)
	endpoint := Endpoint{
		URL:    targetURL,
		Method: "GET",
		Params: params,
		Depth:  depth,
		Source: source,
	}

	c.mu.Lock()
	c.endpoints = append(c.endpoints, endpoint)
	c.mu.Unlock()

	// Extract links
	links := c.extractLinks(bodyStr, targetURL)
	for _, link := range links {
		if c.shouldCrawl(link) {
			c.wg.Add(1)
			go c.crawl(link, depth+1, targetURL)
		}
	}

	// Extract forms
	forms := c.extractForms(bodyStr, targetURL)
	for _, form := range forms {
		formEndpoint := Endpoint{
			URL:    form.Action,
			Method: form.Method,
			Forms:  []Form{form},
			Depth:  depth,
			Source: targetURL,
		}

		c.mu.Lock()
		c.endpoints = append(c.endpoints, formEndpoint)
		c.mu.Unlock()
	}
}

// extractLinks extracts all links from HTML content
func (c *Crawler) extractLinks(html, baseURL string) []string {
	var links []string

	// Match href attributes
	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := hrefRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := c.resolveURL(match[1], baseURL)
			if link != "" {
				links = append(links, link)
			}
		}
	}

	// Match src attributes
	srcRegex := regexp.MustCompile(`src=["']([^"']+)["']`)
	matches = srcRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := c.resolveURL(match[1], baseURL)
			if link != "" {
				links = append(links, link)
			}
		}
	}

	// Match action attributes (forms)
	actionRegex := regexp.MustCompile(`action=["']([^"']+)["']`)
	matches = actionRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := c.resolveURL(match[1], baseURL)
			if link != "" {
				links = append(links, link)
			}
		}
	}

	return utils.UniqueStrings(links)
}

// extractForms extracts all forms from HTML content
func (c *Crawler) extractForms(html, baseURL string) []Form {
	var forms []Form

	formRegex := regexp.MustCompile(`(?s)<form[^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(html, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) > 1 {
			formHTML := formMatch[0]

			// Extract action
			actionRegex := regexp.MustCompile(`action=["']([^"']*)["']`)
			actionMatch := actionRegex.FindStringSubmatch(formHTML)
			action := ""
			if len(actionMatch) > 1 {
				action = c.resolveURL(actionMatch[1], baseURL)
			} else {
				action = baseURL
			}

			// Extract method
			methodRegex := regexp.MustCompile(`method=["']([^"']*)["']`)
			methodMatch := methodRegex.FindStringSubmatch(formHTML)
			method := "GET"
			if len(methodMatch) > 1 {
				method = strings.ToUpper(methodMatch[1])
			}

			// Extract inputs
			inputs := make(map[string]string)
			inputRegex := regexp.MustCompile(`<input[^>]*name=["']([^"']*)["'][^>]*>`)
			inputMatches := inputRegex.FindAllStringSubmatch(formHTML, -1)

			for _, inputMatch := range inputMatches {
				if len(inputMatch) > 1 {
					inputs[inputMatch[1]] = ""
				}
			}

			forms = append(forms, Form{
				Action: action,
				Method: method,
				Inputs: inputs,
			})
		}
	}

	return forms
}

// resolveURL resolves a relative URL to an absolute URL
func (c *Crawler) resolveURL(href, baseURL string) string {
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	parsedHref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := parsedBase.ResolveReference(parsedHref)
	return resolved.String()
}

// shouldCrawl checks if a URL should be crawled
func (c *Crawler) shouldCrawl(targetURL string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// Skip non-HTTP(S) URLs
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Skip fragments and query-only changes
	if parsed.Fragment != "" {
		targetURL = strings.Split(targetURL, "#")[0]
	}

	// Check same domain if configured
	if c.config.SameDomain && parsed.Host != c.baseHost {
		return false
	}

	// Skip already visited
	c.mu.Lock()
	visited := c.visited[targetURL]
	c.mu.Unlock()

	return !visited
}
