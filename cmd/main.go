package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vulnscan",
	Short: "Advanced Web Vulnerability Scanner",
	Long:  "A modular web vulnerability scanner with crawling, passive/active scanning, and reporting capabilities.",
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(crawlCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(compareCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
