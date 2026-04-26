// Mock pfSense API server for integration testing
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RequestLog represents a logged HTTP request
type RequestLog struct {
	Timestamp string            `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
}

var (
	requestLogs []RequestLog
	logMutex    sync.Mutex
	logFile     string
)

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	flag.StringVar(&logFile, "log", "requests.json", "File to write request logs")
	flag.Parse()

	http.HandleFunc("/", handleRequest)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock pfSense API server starting on %s with TLS", addr)

	tlsConfig, err := generateSelfSignedTLSConfig()
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	server := &http.Server{
		Addr:         addr,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// generateSelfSignedTLSConfig creates a TLS config with a self-signed certificate
func generateSelfSignedTLSConfig() (*tls.Config, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mock pfSense"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()

	headers := make(map[string]string)
	for key, values := range r.Header {
		headers[key] = strings.Join(values, ", ")
	}

	reqLog := RequestLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   headers,
		Body:      string(body),
	}

	logMutex.Lock()
	requestLogs = append(requestLogs, reqLog)
	writeLogsToFile()
	logMutex.Unlock()

	log.Printf("%s %s", r.Method, r.URL.Path)

	// Check x-api-key header
	if r.Header.Get("x-api-key") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing x-api-key header"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.URL.Path == "/api/v2/services/dns_resolver/host_overrides" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "ok",
			"data":   []interface{}{},
		})

	case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPost:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "ok",
			"data": map[string]interface{}{
				"id":     1,
				"host":   "test",
				"domain": "example.com",
				"ip":     []string{"192.168.42.23"},
				"descr":  "Managed by Caddy Test",
			},
		})

	case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPatch:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "ok",
			"data": map[string]interface{}{
				"id":     1,
				"host":   "test",
				"domain": "example.com",
				"ip":     []string{"192.168.42.23"},
				"descr":  "Managed by Caddy Test",
			},
		})

	case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodDelete:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "ok",
			"data":   map[string]interface{}{"id": 1},
		})

	case r.URL.Path == "/api/v2/services/dns_resolver/apply" && r.Method == http.MethodPost:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   200,
			"status": "ok",
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
	}
}

func writeLogsToFile() {
	data, err := json.MarshalIndent(requestLogs, "", "  ")
	if err != nil {
		log.Printf("Error marshaling logs: %v", err)
		return
	}
	if err := os.WriteFile(logFile, data, 0644); err != nil {
		log.Printf("Error writing log file: %v", err)
	}
}
