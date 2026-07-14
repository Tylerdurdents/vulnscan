package main

import (
	"fmt"
	"os"

	"github.com/eonedge/vulnscan/pkg/proxy"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [target]",
	Short: "Start a proxy server to capture and analyze traffic",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Get flags
		addr, _ := cmd.Flags().GetString("addr")
		verbose, _ := cmd.Flags().GetBool("verbose")

		fmt.Printf("[*] Starting proxy for target: %s\n", target)
		fmt.Printf("[*] Listening on: %s\n", addr)
		fmt.Printf("[*] Verbose: %v\n", verbose)

		// Create proxy config
		config := proxy.ProxyConfig{
			ListenAddr: addr,
			TargetURL:  target,
			Verbose:    verbose,
		}

		// Create and start proxy
		p := proxy.NewProxy(config)

		fmt.Println("[*] Proxy started. Press Ctrl+C to stop.")

		if err := p.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error starting proxy: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	proxyCmd.Flags().StringP("addr", "a", ":8080", "Listen address")
	proxyCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
}
