package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient wraps http.Client with additional functionality
type HTTPClient struct {
	Client    *http.Client
	UserAgent string
	Headers   map[string]string
}

// NewHTTPClient creates a new HTTP client with default settings
func NewHTTPClient(timeout time.Duration, insecureSkipVerify bool) *HTTPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &HTTPClient{
		Client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		UserAgent: "VulnScan/1.0",
		Headers:   make(map[string]string),
	}
}

// SetUserAgent sets the User-Agent header
func (c *HTTPClient) SetUserAgent(ua string) {
	c.UserAgent = ua
}

// SetHeader sets a custom header
func (c *HTTPClient) SetHeader(key, value string) {
	c.Headers[key] = value
}

// Get performs a GET request
func (c *HTTPClient) Get(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)
	return c.Client.Do(req)
}

// Post performs a POST request with form data
func (c *HTTPClient) Post(targetURL string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setHeaders(req)
	return c.Client.Do(req)
}

// PostJSON performs a POST request with JSON body
func (c *HTTPClient) PostJSON(targetURL string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)
	return c.Client.Do(req)
}

// DoRequest performs a custom HTTP request
func (c *HTTPClient) DoRequest(method, targetURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)
	return c.Client.Do(req)
}

// setHeaders sets default and custom headers on the request
func (c *HTTPClient) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", c.UserAgent)
	for key, value := range c.Headers {
		req.Header.Set(key, value)
	}
}
