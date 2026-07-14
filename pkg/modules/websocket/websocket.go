package websocket

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// WebSocketModule implements WebSocket vulnerability scanning
type WebSocketModule struct{}

// NewWebSocketModule creates a new WebSocket module
func NewWebSocketModule() *WebSocketModule {
	return &WebSocketModule{}
}

func (m *WebSocketModule) Name() string        { return "websocket" }
func (m *WebSocketModule) Description() string  { return "WebSocket vulnerability scanner" }

// Scan scans an endpoint for WebSocket vulnerabilities
func (m *WebSocketModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Check for WebSocket endpoints
	wsPaths := []string{"/ws", "/websocket", "/socket", "/wss", "/sockjs", "/signalr"}
	
	for _, path := range wsPaths {
		testURL := strings.TrimRight(endpoint.URL, "/") + path
		
		// Try to connect with ws:// protocol check
		httpURL := strings.Replace(testURL, "ws://", "http://", 1)
		httpURL = strings.Replace(httpURL, "wss://", "https://", 1)
		
		resp, err := client.Get(httpURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for WebSocket upgrade headers
		upgrade := resp.Header.Get("Upgrade")
		connection := resp.Header.Get("Connection")
		
		if strings.ToLower(upgrade) == "websocket" || strings.Contains(strings.ToLower(connection), "upgrade") {
			vuln := scanner.Vulnerability{
				Type:        "WEBSOCKET_DETECTED",
				Severity:    scanner.SeverityLow,
				URL:         testURL,
				Description: "WebSocket endpoint detected",
				Evidence:    "Upgrade: " + upgrade,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)

			// Check for Cross-Site WebSocket Hijacking (CSWH)
			// by checking if Origin header is validated
			client.SetHeader("Origin", "https://evil.com")
			resp2, err := client.Get(httpURL)
			if err == nil {
				defer resp2.Body.Close()
				if resp2.StatusCode == 101 || resp2.StatusCode == 200 {
					vuln := scanner.Vulnerability{
						Type:        "WEBSOCKET_CSWH",
						Severity:    scanner.SeverityHigh,
						URL:         testURL,
						Description: "WebSocket may be vulnerable to Cross-Site WebSocket Hijacking",
						Evidence:    "Connection accepted from arbitrary origin",
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
				}
			}
			// Remove test header
			delete(client.Headers, "Origin")
		}
	}

	// Check for WebSocket in HTML/JavaScript
	resp, err := client.Get(endpoint.URL)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	// Look for WebSocket usage in page source
	body := ""
	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		body = string(bodyBytes)
	}

	wsPatterns := []string{
		"new WebSocket(",
		"new WebSocket (",
		"ws://",
		"wss://",
		"socket.io",
		"sockjs",
		"signalr",
	}

	for _, pattern := range wsPatterns {
		if strings.Contains(body, pattern) {
			vuln := scanner.Vulnerability{
				Type:        "WEBSOCKET_CLIENT_USAGE",
				Severity:    scanner.SeverityLow,
				URL:         endpoint.URL,
				Description: "WebSocket usage detected in client-side code",
				Evidence:    "Found: " + pattern,
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
			break
		}
	}

	return vulns
}
