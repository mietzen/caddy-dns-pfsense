// Validates that the mock server received expected API requests for pfSense
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// RequestLog represents a logged HTTP request
type RequestLog struct {
	Timestamp string            `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
}

// PfSenseCreateRequest for pfSense host override creation
type PfSenseCreateRequest struct {
	Host   string   `json:"host"`
	Domain string   `json:"domain"`
	IP     []string `json:"ip"`
	Descr  string   `json:"descr"`
}

func main() {
	logFile := flag.String("log", "requests.json", "Request log file to validate")
	flag.Parse()

	data, err := os.ReadFile(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading log file: %v\n", err)
		os.Exit(1)
	}

	var logs []RequestLog
	if err := json.Unmarshal(data, &logs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing log file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d requests in log\n", len(logs))

	errors := validatePfSense(logs)

	if len(errors) > 0 {
		fmt.Println("\nValidation FAILED:")
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
		os.Exit(1)
	}

	fmt.Println("\nValidation PASSED")
}

func validatePfSense(logs []RequestLog) []string {
	var errors []string

	// Expected request sequence for pfSense SetRecords flow:
	// 1. GET /api/v2/services/dns_resolver/host_overrides
	// 2. POST /api/v2/services/dns_resolver/host_override (or PATCH if updating)
	// 3. POST /api/v2/services/dns_resolver/apply

	expectations := []struct {
		method   string
		pathPart string
		validate func(RequestLog) error
	}{
		{"GET", "/api/v2/services/dns_resolver/host_overrides", nil},
		{"POST", "/api/v2/services/dns_resolver/host_override", validatePfSenseCreateRequest},
		{"POST", "/api/v2/services/dns_resolver/apply", nil},
	}

	foundExpectations := make([]bool, len(expectations))

	for _, log := range logs {
		// Check for x-api-key header
		if _, ok := log.Headers["X-Api-Key"]; !ok {
			// Try lowercase variant
			found := false
			for k := range log.Headers {
				if strings.EqualFold(k, "x-api-key") {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Sprintf("Request to %s missing x-api-key header", log.Path))
			}
		}

		for i, exp := range expectations {
			if log.Method == exp.method && strings.Contains(log.Path, exp.pathPart) {
				foundExpectations[i] = true
				if exp.validate != nil {
					if err := exp.validate(log); err != nil {
						errors = append(errors, err.Error())
					}
				}
				fmt.Printf("OK: %s %s\n", log.Method, log.Path)
			}
		}
	}

	for i, found := range foundExpectations {
		if !found {
			errors = append(errors, fmt.Sprintf("Missing expected request: %s %s",
				expectations[i].method, expectations[i].pathPart))
		}
	}

	return errors
}

func validatePfSenseCreateRequest(log RequestLog) error {
	var req PfSenseCreateRequest
	if err := json.Unmarshal([]byte(log.Body), &req); err != nil {
		return fmt.Errorf("invalid host_override request body: %v", err)
	}

	if req.Domain != "example.com" {
		return fmt.Errorf("unexpected domain: got %q, want %q", req.Domain, "example.com")
	}

	ipFound := false
	for _, ip := range req.IP {
		if ip == "192.168.42.23" {
			ipFound = true
			break
		}
	}
	if !ipFound {
		return fmt.Errorf("expected IP %q not found in %v", "192.168.42.23", req.IP)
	}

	if req.Descr != "Managed by Caddy Test" {
		return fmt.Errorf("unexpected description: got %q, want %q", req.Descr, "Managed by Caddy Test")
	}

	fmt.Printf("  -> Adding host %q to domain %q with IPs %v\n", req.Host, req.Domain, req.IP)
	return nil
}
