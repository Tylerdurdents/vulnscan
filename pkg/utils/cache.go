package utils

import (
	"net/http"
	"sync"
	"time"
)

// CacheEntry represents a cached HTTP response
type CacheEntry struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
	TTL        time.Duration
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Since(e.Timestamp) > e.TTL
}

// ResponseCache provides HTTP response caching
type ResponseCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

// NewResponseCache creates a new response cache
func NewResponseCache(ttl time.Duration, maxSize int) *ResponseCache {
	cache := &ResponseCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached response
func (c *ResponseCache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists || entry.IsExpired() {
		return nil, false
	}

	return entry, true
}

// Set stores a response in the cache
func (c *ResponseCache) Set(key string, statusCode int, headers http.Header, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is full
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		Timestamp:  time.Now(),
		TTL:        c.ttl,
	}
}

// Delete removes an entry from the cache
func (c *ResponseCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}

// Clear removes all entries from the cache
func (c *ResponseCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
}

// Size returns the number of entries in the cache
func (c *ResponseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// cleanup removes expired entries periodically
func (c *ResponseCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for key, entry := range c.entries {
			if entry.IsExpired() {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// evictOldest removes the oldest entry
func (c *ResponseCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// GenerateCacheKey generates a cache key from method and URL
func GenerateCacheKey(method, url string) string {
	return method + ":" + url
}
