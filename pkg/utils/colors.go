package utils

import (
	"fmt"
	"os"
	"runtime"
)

// Color codes
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	
	// Bold colors
	ColorBoldRed     = "\033[1;31m"
	ColorBoldGreen   = "\033[1;32m"
	ColorBoldYellow  = "\033[1;33m"
	ColorBoldBlue    = "\033[1;34m"
	ColorBoldMagenta = "\033[1;35m"
	ColorBoldCyan    = "\033[1;36m"
	ColorBoldWhite   = "\033[1;37m"
	
	// Background colors
	ColorBgRed     = "\033[41m"
	ColorBgGreen   = "\033[42m"
	ColorBgYellow  = "\033[43m"
	ColorBgBlue    = "\033[44m"
)

// ColorSupport checks if the terminal supports colors
var ColorSupport = checkColorSupport()

func checkColorSupport() bool {
	// Windows 10+ supports colors
	if runtime.GOOS == "windows" {
		return true
	}
	
	// Check for NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	
	// Check for TERM environment variable
	term := os.Getenv("TERM")
	if term == "dumb" {
		return false
	}
	
	// Check if stdout is a terminal
	if os.Getenv("TERM") == "" {
		return false
	}
	
	return true
}

// Colorize wraps text with color codes
func Colorize(text, color string) string {
	if !ColorSupport {
		return text
	}
	return color + text + ColorReset
}

// Red returns red colored text
func Red(text string) string {
	return Colorize(text, ColorRed)
}

// Green returns green colored text
func Green(text string) string {
	return Colorize(text, ColorGreen)
}

// Yellow returns yellow colored text
func Yellow(text string) string {
	return Colorize(text, ColorYellow)
}

// Blue returns blue colored text
func Blue(text string) string {
	return Colorize(text, ColorBlue)
}

// Magenta returns magenta colored text
func Magenta(text string) string {
	return Colorize(text, ColorMagenta)
}

// Cyan returns cyan colored text
func Cyan(text string) string {
	return Colorize(text, ColorCyan)
}

// White returns white colored text
func White(text string) string {
	return Colorize(text, ColorWhite)
}

// BoldRed returns bold red colored text
func BoldRed(text string) string {
	return Colorize(text, ColorBoldRed)
}

// BoldGreen returns bold green colored text
func BoldGreen(text string) string {
	return Colorize(text, ColorBoldGreen)
}

// BoldYellow returns bold yellow colored text
func BoldYellow(text string) string {
	return Colorize(text, ColorBoldYellow)
}

// BoldBlue returns bold blue colored text
func BoldBlue(text string) string {
	return Colorize(text, ColorBoldBlue)
}

// PrintSuccess prints a success message in green
func PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[+]%s %s\n", Green(""), ColorReset, msg)
}

// PrintError prints an error message in red
func PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[!]%s %s\n", Red(""), ColorReset, msg)
}

// PrintWarning prints a warning message in yellow
func PrintWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[-]%s %s\n", Yellow(""), ColorReset, msg)
}

// PrintInfo prints an info message in blue
func PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[*]%s %s\n", Blue(""), ColorReset, msg)
}

// PrintDebug prints a debug message in cyan
func PrintDebug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[~]%s %s\n", Cyan(""), ColorReset, msg)
}

// PrintBanner prints a banner
func PrintBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗║
║   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝║
║                                                              ║
║   Advanced Web Vulnerability Scanner                         ║
║   Version 1.0.0                                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(Cyan(banner))
}

// PrintScanResult prints scan results with colors
func PrintScanResult(vulnType, severity, url, description string) {
	var severityColor string
	
	switch severity {
	case "CRITICAL":
		severityColor = ColorBoldRed
	case "HIGH":
		severityColor = ColorRed
	case "MEDIUM":
		severityColor = ColorYellow
	case "LOW":
		severityColor = ColorGreen
	default:
		severityColor = ColorWhite
	}
	
	fmt.Printf("  %s%-20s%s %s%-10s%s %s\n",
		ColorBoldWhite, vulnType, ColorReset,
		severityColor, severity, ColorReset,
		url)
}

// PrintProgressBar prints a progress bar
func PrintProgressBar(current, total int, prefix string) {
	width := 40
	percent := float64(current) / float64(total)
	filled := int(float64(width) * percent)
	empty := width - filled

	bar := Green("█") + Green(fmt.Sprintf("%s", repeat("█", filled))) + 
		White(fmt.Sprintf("%s", repeat("░", empty)))

	fmt.Printf("\r%s [%s] %.1f%%", prefix, bar, percent*100)
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
