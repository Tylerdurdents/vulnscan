package graphql

import (
	"io"
	"strings"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// GraphQLModule implements GraphQL vulnerability scanning
type GraphQLModule struct{}

// NewGraphQLModule creates a new GraphQL module
func NewGraphQLModule() *GraphQLModule {
	return &GraphQLModule{}
}

func (m *GraphQLModule) Name() string        { return "graphql" }
func (m *GraphQLModule) Description() string  { return "GraphQL vulnerability scanner" }

// Scan scans an endpoint for GraphQL vulnerabilities
func (m *GraphQLModule) Scan(client *utils.HTTPClient, endpoint crawler.Endpoint) []scanner.Vulnerability {
	var vulns []scanner.Vulnerability

	// Check if endpoint might be GraphQL
	graphqlPaths := []string{"/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"}
	isGraphQL := false

	for _, path := range graphqlPaths {
		if strings.Contains(strings.ToLower(endpoint.URL), path) {
			isGraphQL = true
			break
		}
	}

	// Test for GraphQL introspection
	introspectionQuery := `{"query": "{ __schema { types { name } } }"}`
	resp, err := client.PostJSON(endpoint.URL, introspectionQuery)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "types") {
			isGraphQL = true
			vuln := scanner.Vulnerability{
				Type:        "GRAPHQL_INTROSPECTION",
				Severity:    scanner.SeverityHigh,
				URL:         endpoint.URL,
				Description: "GraphQL introspection is enabled - exposes schema",
				Evidence:    "Introspection query returned schema data",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Test for GraphQL query batching
	batchQuery := `[{"query": "{ __typename }"}, {"query": "{ __typename }"}]`
	resp, err = client.PostJSON(endpoint.URL, batchQuery)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "__typename") && strings.Count(bodyStr, "__typename") > 1 {
			vuln := scanner.Vulnerability{
				Type:        "GRAPHQL_BATCHING",
				Severity:    scanner.SeverityMedium,
				URL:         endpoint.URL,
				Description: "GraphQL query batching is enabled - can be used for DoS",
				Evidence:    "Batch query accepted",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Test for GraphQL field suggestion
	suggestionQuery := `{"query": "{ user { naem } }"}`
	resp, err = client.PostJSON(endpoint.URL, suggestionQuery)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "Did you mean") || strings.Contains(bodyStr, "suggestion") {
			vuln := scanner.Vulnerability{
				Type:        "GRAPHQL_FIELD_SUGGESTION",
				Severity:    scanner.SeverityLow,
				URL:         endpoint.URL,
				Description: "GraphQL field suggestions enabled - leaks schema information",
				Evidence:    "Field suggestion returned",
				Timestamp:   utils.GetCurrentTime(),
			}
			vulns = append(vulns, vuln)
		}
	}

	// Test for GraphQL depth limit bypass
	deepQuery := `{"query": "{ __typename { __typename { __typename { __typename { __typename } } } } }"}`
	resp, err = client.PostJSON(endpoint.URL, deepQuery)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if !strings.Contains(bodyStr, "depth") && !strings.Contains(bodyStr, "limit") {
			if isGraphQL {
				vuln := scanner.Vulnerability{
					Type:        "GRAPHQL_NO_DEPTH_LIMIT",
					Severity:    scanner.SeverityMedium,
					URL:         endpoint.URL,
					Description: "GraphQL has no depth limit - vulnerable to deeply nested queries",
					Evidence:    "Deep query accepted",
					Timestamp:   utils.GetCurrentTime(),
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	// Test for GraphQL playground
	playgroundPaths := []string{"/playground", "/graphiql", "/graphql-playground"}
	for _, path := range playgroundPaths {
		testURL := strings.TrimRight(endpoint.URL, "/") + path
		resp, err := client.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				if strings.Contains(bodyStr, "playground") || strings.Contains(bodyStr, "graphiql") {
					vuln := scanner.Vulnerability{
						Type:        "GRAPHQL_PLAYGROUND",
						Severity:    scanner.SeverityMedium,
						URL:         testURL,
						Description: "GraphQL playground is exposed - allows arbitrary queries",
						Evidence:    "Playground UI accessible",
						Timestamp:   utils.GetCurrentTime(),
					}
					vulns = append(vulns, vuln)
					break
				}
			}
		}
	}

	return vulns
}
