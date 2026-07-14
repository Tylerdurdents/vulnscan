package utils

import (
	"testing"
	"time"
)

func TestNewHTTPClient(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	if client == nil {
		t.Fatal("Failed to create HTTP client")
	}
	if client.UserAgent != "VulnScan/1.0" {
		t.Errorf("Expected UserAgent 'VulnScan/1.0', got '%s'", client.UserAgent)
	}
}

func TestSetUserAgent(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetUserAgent("TestAgent/1.0")
	if client.UserAgent != "TestAgent/1.0" {
		t.Errorf("Expected UserAgent 'TestAgent/1.0', got '%s'", client.UserAgent)
	}
}

func TestSetHeader(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetHeader("X-Custom", "test-value")
	if client.Headers["X-Custom"] != "test-value" {
		t.Errorf("Expected header 'test-value', got '%s'", client.Headers["X-Custom"])
	}
}

func TestSetCookie(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetCookie("session", "abc123")
	if len(client.Cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(client.Cookies))
	}
	if client.Cookies[0].Name != "session" || client.Cookies[0].Value != "abc123" {
		t.Errorf("Cookie mismatch: %s=%s", client.Cookies[0].Name, client.Cookies[0].Value)
	}
}

func TestSetBearerToken(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetBearerToken("mytoken")
	if client.Headers["Authorization"] != "Bearer mytoken" {
		t.Errorf("Expected 'Bearer mytoken', got '%s'", client.Headers["Authorization"])
	}
}

func TestSetBasicAuth(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetBasicAuth("user", "pass")
	if client.Headers["Authorization"] != "Basic user:pass" {
		t.Errorf("Expected 'Basic user:pass', got '%s'", client.Headers["Authorization"])
	}
}

func TestSetAuthConfig(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)

	// Test cookie auth
	client.SetAuthConfig(AuthConfig{Type: "cookie", Value: "token=abc123"})
	if len(client.Cookies) != 1 {
		t.Errorf("Expected 1 cookie, got %d", len(client.Cookies))
	}

	// Test bearer auth
	client2 := NewHTTPClient(30*time.Second, true)
	client2.SetAuthConfig(AuthConfig{Type: "bearer", Value: "mytoken"})
	if client2.Headers["Authorization"] != "Bearer mytoken" {
		t.Errorf("Expected 'Bearer mytoken', got '%s'", client2.Headers["Authorization"])
	}

	// Test basic auth
	client3 := NewHTTPClient(30*time.Second, true)
	client3.SetAuthConfig(AuthConfig{Type: "basic", Value: "user:pass"})
	if client3.Headers["Authorization"] != "Basic user:pass" {
		t.Errorf("Expected 'Basic user:pass', got '%s'", client3.Headers["Authorization"])
	}

	// Test header auth
	client4 := NewHTTPClient(30*time.Second, true)
	client4.SetAuthConfig(AuthConfig{Type: "header", Header: "X-API-Key", Value: "key123"})
	if client4.Headers["X-API-Key"] != "key123" {
		t.Errorf("Expected 'key123', got '%s'", client4.Headers["X-API-Key"])
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10, 20)
	if limiter == nil {
		t.Fatal("Failed to create rate limiter")
	}

	// Should not block for burst
	start := time.Now()
	for i := 0; i < 20; i++ {
		limiter.Wait()
	}
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("Rate limiter too slow: %v", elapsed)
	}
}

func TestSetRateLimit(t *testing.T) {
	client := NewHTTPClient(30*time.Second, true)
	client.SetRateLimit(10, 20)
	if client.Limiter == nil {
		t.Fatal("Expected rate limiter to be set")
	}
}
