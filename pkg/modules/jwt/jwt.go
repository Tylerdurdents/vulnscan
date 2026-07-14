package jwt

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// JWTModule implements JWT vulnerability scanning
type JWTModule struct{}

// NewJWTModule creates a new JWT module
func NewJWTModule() *JWTModule {
	return &JWTModule{}
}

func (m *JWTModule) Name() string        { return "jwt" }
func (m *JWTModule) Description() string  { return "JWT (JSON Web Token) vulnerability scanner" }

// JWTHeader represents the JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Scan scans an endpoint for JWT vulnerabilities
func (m *JWTModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Get the page to check for JWT tokens
	resp, err := client.Get(endpoint.URL)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulns
	}
	bodyStr := string(body)

	// Check for JWT tokens in response
	jwtTokens := extractJWTTokens(bodyStr)

	// Check cookies for JWT
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if isJWT(cookie.Value) {
			jwtTokens = append(jwtTokens, cookie.Value)
		}
	}

	// Analyze each JWT token
	for _, token := range jwtTokens {
		// Check for None algorithm vulnerability
		if checkNoneAlgorithm(token) {
			vuln := scanner.Vulnerability{
				Type:     "JWT_NONE_ALGORITHM",
				Severity: scanner.SeverityCritical,
				URL:      endpoint.URL,
				Description: "JWT accepts 'none' algorithm - allows token forgery",
				Evidence:    "Token: " + truncateToken(token),
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}

		// Check for weak algorithms
		if checkWeakAlgorithm(token) {
			vuln := scanner.Vulnerability{
				Type:     "JWT_WEAK_ALGORITHM",
				Severity: scanner.SeverityHigh,
				URL:      endpoint.URL,
				Description: "JWT uses weak algorithm (HS256 with known secret or none)",
				Evidence:    "Token: " + truncateToken(token),
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}

		// Check for missing expiration
		if checkMissingExpiration(token) {
			vuln := scanner.Vulnerability{
				Type:     "JWT_MISSING_EXPIRATION",
				Severity: scanner.SeverityMedium,
				URL:      endpoint.URL,
				Description: "JWT token missing expiration claim (exp)",
				Evidence:    "Token: " + truncateToken(token),
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Check for JWT in Authorization header by sending test request
	testResp, err := client.Get(endpoint.URL)
	if err == nil {
		defer testResp.Body.Close()
		// Check if response contains JWT-related error messages
		testBody, _ := io.ReadAll(testResp.Body)
		testBodyStr := string(testBody)
		
		if strings.Contains(testBodyStr, "invalid token") || 
		   strings.Contains(testBodyStr, "jwt") ||
		   strings.Contains(testBodyStr, "Bearer") {
			// Endpoint likely uses JWT
			if len(jwtTokens) == 0 {
				vuln := scanner.Vulnerability{
					Type:     "JWT_DETECTED",
					Severity: scanner.SeverityLow,
					URL:      endpoint.URL,
					Description: "Endpoint appears to use JWT authentication",
					Evidence:    "JWT-related error message detected",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// extractJWTTokens extracts JWT tokens from a string
func extractJWTTokens(content string) []string {
	var tokens []string
	parts := strings.Split(content, " ")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if isJWT(part) {
			tokens = append(tokens, part)
		}
	}

	// Also check for JWT in common patterns
	patterns := []string{
		"Bearer ",
		"token=",
		"jwt=",
		"access_token=",
	}

	for _, pattern := range patterns {
		idx := strings.Index(content, pattern)
		if idx != -1 {
			start := idx + len(pattern)
			end := strings.IndexAny(content[start:], " \t\n\"';,")
			if end == -1 {
				end = len(content)
			} else {
				end += start
			}
			token := content[start:end]
			if isJWT(token) {
				tokens = append(tokens, token)
			}
		}
	}

	return tokens
}

// isJWT checks if a string looks like a JWT token
func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Try to decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	return header.Alg != ""
}

// checkNoneAlgorithm checks if JWT uses none algorithm
func checkNoneAlgorithm(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	return strings.ToLower(header.Alg) == "none"
}

// checkWeakAlgorithm checks if JWT uses a weak algorithm
func checkWeakAlgorithm(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	weakAlgs := []string{"hs256", "hs384", "hs512"}
	alg := strings.ToLower(header.Alg)
	for _, weak := range weakAlgs {
		if alg == weak {
			return true
		}
	}

	return false
}

// checkMissingExpiration checks if JWT is missing expiration claim
func checkMissingExpiration(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	_, hasExp := payload["exp"]
	return !hasExp
}

// truncateToken truncates a token for display
func truncateToken(token string) string {
	if len(token) > 50 {
		return token[:50] + "..."
	}
	return token
}
