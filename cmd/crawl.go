package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/eonedge/vulnscan/pkg/crawler"
	"github.com/spf13/cobra"
)

var crawlCmd = &cobra.Command{
	Use:   "crawl [target]",
	Short: "Crawl a target URL and discover endpoints",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		depth, _ := cmd.Flags().GetInt("depth")
		headless, _ := cmd.Flags().GetBool("headless")
		output, _ := cmd.Flags().GetString("output")
		threads, _ := cmd.Flags().GetInt("threads")

		fmt.Printf("[*] Crawling: %s\n", target)
		fmt.Printf("[*] Max depth: %d\n", depth)
		fmt.Printf("[*] Threads: %d\n", threads)
		fmt.Printf("[*] Headless: %v\n", headless)

		// Create crawler config
		config := crawler.CrawlerConfig{
			MaxDepth:  depth,
			MaxPages:  100,
			Threads:   threads,
			Timeout:   30 * time.Second,
			UserAgent: "VulnScan/1.0",
			SameDomain: true,
		}

		// Create and run crawler
		c := crawler.NewCrawler(config)
		endpoints, err := c.Crawl(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error crawling: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Found %d endpoints\n", len(endpoints))

		// Save results to file
		data, err := json.MarshalIndent(endpoints, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error marshaling results: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error writing output: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Results saved to %s\n", output)
	},
}

func init() {
	crawlCmd.Flags().IntP("depth", "d", 3, "Maximum crawl depth")
	crawlCmd.Flags().BoolP("headless", "H", false, "Use headless browser for JS-heavy sites")
	crawlCmd.Flags().StringP("output", "o", "endpoints.json", "Output file path")
	crawlCmd.Flags().IntP("threads", "t", 5, "Number of concurrent threads")
}
