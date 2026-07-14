package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// NormalizeURL normalizes a URL by adding scheme if missing
func NormalizeURL(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return parsed.String(), nil
}

// GetBaseURL returns the base URL (scheme + host) from a full URL
func GetBaseURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), nil
}

// IsSameDomain checks if two URLs belong to the same domain
func IsSameDomain(url1, url2 string) bool {
	parsed1, err := url.Parse(url1)
	if err != nil {
		return false
	}

	parsed2, err := url.Parse(url2)
	if err != nil {
		return false
	}

	return parsed1.Host == parsed2.Host
}

// ExtractParams extracts query parameters from a URL
func ExtractParams(rawURL string) map[string]string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := make(map[string]string)
	for key, values := range parsed.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	return params
}

// InjectParam injects a value into a URL parameter
func InjectParam(rawURL, param, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	query := parsed.Query()
	query.Set(param, value)
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

// ContainsPattern checks if a string contains a regex pattern
func ContainsPattern(input, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(input)
}

// CompileRegex compiles a regex pattern
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

// ExtractContext extracts surrounding context around a match in a string
func ExtractContext(body, match string) string {
	idx := strings.Index(body, match)
	if idx == -1 {
		return ""
	}

	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 100
	if end > len(body) {
		end = len(body)
	}

	return "..." + body[start:end] + "..."
}

// UniqueStrings returns a slice with unique strings
func UniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// JoinURL joins a base URL with a path
func JoinURL(base, path string) string {
	if !strings.HasSuffix(base, "/") && !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	return base + path
}

// GetCurrentTime returns the current time
func GetCurrentTime() time.Time {
	return time.Now()
}
