package main

import (
	"fmt"
	"os"

	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare [scan1.json] [scan2.json]",
	Short: "Compare two scan results",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		scan1File := args[0]
		scan2File := args[1]

		// Get flags
		output, _ := cmd.Flags().GetString("output")

		fmt.Printf("[*] Comparing scan results:\n")
		fmt.Printf("    Scan 1: %s\n", scan1File)
		fmt.Printf("    Scan 2: %s\n", scan2File)

		// Load scan results
		scan1, err := scanner.LoadScanResult(scan1File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error loading scan 1: %v\n", err)
			os.Exit(1)
		}

		scan2, err := scanner.LoadScanResult(scan2File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error loading scan 2: %v\n", err)
			os.Exit(1)
		}

		// Compare scans
		comparison := scanner.CompareScans(scan1, scan2)

		// Print comparison
		scanner.PrintComparison(comparison)

		// Save comparison if output specified
		if output != "" {
			if err := scanner.SaveComparison(comparison, output); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error saving comparison: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\n[+] Comparison saved to %s\n", output)
		}
	},
}

func init() {
	compareCmd.Flags().StringP("output", "o", "", "Output file path for comparison")
}
