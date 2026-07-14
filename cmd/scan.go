package main

import (
	"fmt"
	"os"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/eonedge/vulnscan/pkg/modules"
	"github.com/eonedge/vulnscan/pkg/reporter"
	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan a target URL for vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		output, _ := cmd.Flags().GetString("output")
		threads, _ := cmd.Flags().GetInt("threads")
		moduleNames, _ := cmd.Flags().GetStringSlice("modules")
		auth, _ := cmd.Flags().GetString("auth")
		authType, _ := cmd.Flags().GetString("auth-type")
		headless, _ := cmd.Flags().GetBool("headless")
		depth, _ := cmd.Flags().GetInt("depth")
		format, _ := cmd.Flags().GetString("format")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		payloadFile, _ := cmd.Flags().GetString("payloads")

		fmt.Printf("[*] Scanning: %s\n", target)
		fmt.Printf("[*] Modules: %v\n", moduleNames)
		fmt.Printf("[*] Threads: %d\n", threads)
		fmt.Printf("[*] Output: %s\n", output)
		fmt.Printf("[*] Format: %s\n", format)
		if rateLimit > 0 {
			fmt.Printf("[*] Rate limit: %d req/s\n", rateLimit)
		}
		if payloadFile != "" {
			fmt.Printf("[*] Custom payloads: %s\n", payloadFile)
		}

		// Parse auth config
		authConfig := utils.AuthConfig{}
		if auth != "" {
			authConfig.Type = authType
			authConfig.Value = auth
			if authType == "header" {
				authHeader, _ := cmd.Flags().GetString("auth-header")
				authConfig.Header = authHeader
			}
			fmt.Printf("[*] Using authentication: %s\n", authType)
		}
		if headless {
			fmt.Printf("[*] Using headless browser\n")
		}

		// Step 1: Crawl the target
		fmt.Println("\n[*] Step 1: Crawling target...")
		crawlConfig := crawler.CrawlerConfig{
			MaxDepth:   depth,
			MaxPages:   100,
			Threads:    threads,
			Timeout:    30 * time.Second,
			UserAgent:  "VulnScan/1.0",
			SameDomain: true,
		}

		c := crawler.NewCrawler(crawlConfig)
		endpoints, err := c.Crawl(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error crawling: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Found %d endpoints\n", len(endpoints))

		// Step 2: Scan for vulnerabilities
		fmt.Println("\n[*] Step 2: Scanning for vulnerabilities...")
		scanConfig := scanner.ScannerConfig{
			Threads:   threads,
			Timeout:   30 * time.Second,
			UserAgent: "VulnScan/1.0",
			Modules:   moduleNames,
			Auth:      authConfig,
			RateLimit: rateLimit,
		}

		s := scanner.NewScanner(scanConfig)

		// Register modules
		if payloadFile != "" {
			// Load modules with custom payloads
			customModules, err := modules.GetModulesWithPayloads(payloadFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error loading payloads: %v\n", err)
				os.Exit(1)
			}
			for _, module := range customModules {
				s.RegisterModule(module)
			}
		} else {
			// Register all default modules
			allModules := modules.GetAllModules()
			for _, module := range allModules {
				s.RegisterModule(module)
			}
		}

		// Run scan
		result, err := s.Scan(endpoints)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error scanning: %v\n", err)
			os.Exit(1)
		}

		result.Target = target
		fmt.Printf("[+] Found %d vulnerabilities\n", len(result.Vulnerabilities))

		// Step 3: Generate report
		fmt.Println("\n[*] Step 3: Generating report...")
		reportFormat := reporter.ReportFormat(format)
		r := reporter.NewReporter(reportFormat, output)

		if err := r.Generate(result); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error generating report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Report saved to %s\n", output)

		// Print summary
		fmt.Println("\n[*] Scan Summary:")
		fmt.Printf("    Target: %s\n", target)
		fmt.Printf("    Endpoints scanned: %d\n", result.Endpoints)
		fmt.Printf("    Vulnerabilities found: %d\n", len(result.Vulnerabilities))
		fmt.Printf("    Duration: %v\n", result.Duration)

		if len(result.Vulnerabilities) > 0 {
			fmt.Println("\n[!] Vulnerabilities by severity:")
			severityCount := make(map[string]int)
			for _, vuln := range result.Vulnerabilities {
				severityCount[string(vuln.Severity)]++
			}
			for severity, count := range severityCount {
				fmt.Printf("    %s: %d\n", severity, count)
			}
		}
	},
}

func init() {
	scanCmd.Flags().StringP("output", "o", "report.json", "Output file path")
	scanCmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
	scanCmd.Flags().StringSliceP("modules", "m", []string{"sqli", "xss"}, "Modules to use")
	scanCmd.Flags().StringP("auth", "a", "", "Authentication value (token, cookie, user:pass)")
	scanCmd.Flags().StringP("auth-type", "", "cookie", "Authentication type (cookie, bearer, basic, header)")
	scanCmd.Flags().StringP("auth-header", "", "X-Custom-Header", "Custom header name for header auth type")
	scanCmd.Flags().BoolP("headless", "H", false, "Use headless browser for JS-heavy sites")
	scanCmd.Flags().IntP("depth", "d", 3, "Maximum crawl depth")
	scanCmd.Flags().StringP("format", "f", "json", "Report format (json, csv, html)")
	scanCmd.Flags().IntP("rate-limit", "r", 0, "Rate limit (requests per second, 0 = unlimited)")
	scanCmd.Flags().StringP("payloads", "p", "", "Custom payloads file path")
}
