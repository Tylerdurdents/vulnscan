package race

import (
	"strings"
	"sync"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// RaceModule implements race condition vulnerability scanning
type RaceModule struct{}

// NewRaceModule creates a new Race module
func NewRaceModule() *RaceModule {
	return &RaceModule{}
}

func (m *RaceModule) Name() string        { return "race" }
func (m *RaceModule) Description() string  { return "Race condition vulnerability scanner" }

// Scan scans an endpoint for race condition vulnerabilities
func (m *RaceModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Test for race condition on forms
	for _, form := range endpoint.Forms {
		if form.Method != "POST" {
			continue
		}

		// Check for common race condition vulnerable endpoints
		racePatterns := []string{
			"transfer",
			"withdraw",
			"redeem",
			"coupon",
			"gift",
			"apply",
			"vote",
			"like",
			"follow",
			"subscribe",
			"purchase",
			"buy",
			"order",
			"checkout",
			"payment",
		}

		isVulnerable := false
		for _, pattern := range racePatterns {
			if containsIgnoreCase(form.Action, pattern) || containsIgnoreCase(endpoint.URL, pattern) {
				isVulnerable = true
				break
			}
		}

		if !isVulnerable {
			continue
		}

		// Send concurrent requests
		numRequests := 10
		var wg sync.WaitGroup
		results := make([]int, numRequests)
		errors := make([]error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				// Prepare form data
				values := make(map[string][]string)
				for k, v := range form.Inputs {
					values[k] = []string{v}
				}

				resp, err := client.Post(form.Action, values)
				if err != nil {
					errors[index] = err
					return
				}
				defer resp.Body.Close()

				results[index] = resp.StatusCode
			}(i)
		}

		wg.Wait()

		// Analyze results
		successCount := 0
		for _, status := range results {
			if status >= 200 && status < 300 {
				successCount++
			}
		}

		// If multiple requests succeeded, it might be a race condition
		if successCount > 1 {
			vuln := scanner.Vulnerability{
				Type:     "RACE_CONDITION",
				Severity: scanner.SeverityHigh,
				URL:      form.Action,
				Description: "Possible race condition - multiple concurrent requests succeeded",
				Evidence:    "Success rate: " + string(rune(successCount+'0')) + "/" + string(rune(numRequests+'0')),
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Test for TOCTOU (Time of Check to Time of Use)
	if len(endpoint.Params) > 0 {
		// Send two requests in quick succession
		resp1, err := client.Get(endpoint.URL)
		if err == nil {
			defer resp1.Body.Close()
		}

		// Small delay
		time.Sleep(10 * time.Millisecond)

		resp2, err := client.Get(endpoint.URL)
		if err == nil {
			defer resp2.Body.Close()
		}

		// Check if responses differ significantly
		if resp1 != nil && resp2 != nil {
			if resp1.StatusCode != resp2.StatusCode {
				vuln := scanner.Vulnerability{
					Type:     "TOCTOU",
					Severity: scanner.SeverityMedium,
					URL:      endpoint.URL,
					Description: "Possible TOCTOU vulnerability - responses differ between requests",
					Evidence:    "Status codes: " + string(rune(resp1.StatusCode)) + " vs " + string(rune(resp2.StatusCode)),
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// containsIgnoreCase checks if a string contains a substring (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	s, substr = toLower(s), toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	return strings.ToLower(s)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
