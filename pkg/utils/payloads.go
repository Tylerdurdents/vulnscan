package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Payload represents a scanning payload
type Payload struct {
	Value       string
	Pattern     string
	Description string
}

// LoadPayloadsFromFile loads payloads from a file
// File format: one payload per line, or payload|pattern|description
func LoadPayloadsFromFile(filePath string) ([]Payload, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	var payloads []Payload
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		payload := Payload{
			Value: parts[0],
		}

		if len(parts) > 1 {
			payload.Pattern = parts[1]
		}
		if len(parts) > 2 {
			payload.Description = parts[2]
		}

		payloads = append(payloads, payload)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read payload file: %w", err)
	}

	return payloads, nil
}

// LoadStringsFromFile loads strings from a file (one per line)
func LoadStringsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return lines, nil
}
