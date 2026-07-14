package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eonedge/vulnscan/pkg/utils"
)

// Request represents a captured HTTP request
type Request struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// Response represents a captured HTTP response
type Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// Transaction represents a complete HTTP transaction (request + response)
type Transaction struct {
	Request  Request  `json:"request"`
	Response Response `json:"response"`
	Duration int64    `json:"duration_ms"`
}

// ProxyConfig holds configuration for the proxy
type ProxyConfig struct {
	ListenAddr string
	TargetURL  string
	Verbose    bool
}

// Proxy handles HTTP proxy operations
type Proxy struct {
	config       ProxyConfig
	server       *http.Server
	transactions []Transaction
	mu           sync.Mutex
	logger       *utils.Logger
}

// NewProxy creates a new proxy instance
func NewProxy(config ProxyConfig) *Proxy {
	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}

	return &Proxy{
		config:       config,
		transactions: []Transaction{},
		logger:       utils.NewLogger(utils.INFO, "PROXY"),
	}
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:    p.config.ListenAddr,
		Handler: http.HandlerFunc(p.handleRequest),
	}

	p.logger.Info("Starting proxy on %s", p.config.ListenAddr)
	return p.server.ListenAndServe()
}

// Stop stops the proxy server
func (p *Proxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

// GetTransactions returns all captured transactions
func (p *Proxy) GetTransactions() []Transaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.transactions
}

// handleRequest handles incoming HTTP requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Capture request
	req := Request{
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   make(map[string]string),
		Timestamp: startTime,
	}

	for key, values := range r.Header {
		req.Headers[key] = strings.Join(values, ", ")
	}

	// Read request body
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			req.Body = string(body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
	}

	if p.config.Verbose {
		p.logger.Debug("Request: %s %s", req.Method, req.URL)
	}

	// Forward request to target
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create new request
	targetURL := p.config.TargetURL + r.URL.String()
	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		proxyReq.Header[key] = values
	}

	// Send request
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Capture response
	respData := Response{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Timestamp:  time.Now(),
	}

	for key, values := range resp.Header {
		respData.Headers[key] = strings.Join(values, ", ")
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		respData.Body = string(body)
	}

	// Calculate duration
	duration := time.Since(startTime)

	// Store transaction
	transaction := Transaction{
		Request:  req,
		Response: respData,
		Duration: duration.Milliseconds(),
	}

	p.mu.Lock()
	p.transactions = append(p.transactions, transaction)
	p.mu.Unlock()

	if p.config.Verbose {
		p.logger.Debug("Response: %d (%dms)", resp.StatusCode, duration.Milliseconds())
	}

	// Copy response to client
	for key, values := range resp.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
