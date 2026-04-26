package pfsense

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(handler)
}

func newTestProvider(t *testing.T, serverURL string) *Provider {
	t.Helper()
	host := strings.TrimPrefix(serverURL, "https://")
	return &Provider{
		Host:     host,
		APIKey:   "test-api-key",
		Insecure: true,
	}
}

func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

// authMiddleware validates the x-api-key header is present and correct on every request.
func authMiddleware(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key")
		if key == "" {
			t.Errorf("missing x-api-key header on %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if key != "test-api-key" {
			t.Errorf("wrong x-api-key: got %q, want %q", key, "test-api-key")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func TestTrimZone(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected string
	}{
		{"with trailing dot", "example.com.", "example.com"},
		{"without trailing dot", "example.com", "example.com"},
		{"empty string", "", ""},
		{"only dot", ".", ""},
		{"multiple dots", "sub.example.com.", "sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimZone(tt.zone)
			if result != tt.expected {
				t.Errorf("trimZone(%q) = %q, want %q", tt.zone, result, tt.expected)
			}
		})
	}
}

func TestResolveHostAndDomain(t *testing.T) {
	tests := []struct {
		name           string
		recordName     string
		zone           string
		expectedHost   string
		expectedDomain string
	}{
		{"normal subdomain", "www", "example.com", "www", "example.com"},
		{"zone apex with @", "@", "example.com", "example", "com"},
		{"zone apex empty", "", "example.com", "example", "com"},
		{"subdomain with trailing dot zone", "api", "example.com.", "api", "example.com"},
		{"apex with trailing dot zone", "@", "my_domain.org.", "my_domain", "org"},
		{"single label zone apex", "@", "localhost", "localhost", ""},
		{"deep subdomain", "deep.sub", "example.com", "deep.sub", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, domain := resolveHostAndDomain(tt.recordName, tt.zone)
			if host != tt.expectedHost || domain != tt.expectedDomain {
				t.Errorf("resolveHostAndDomain(%q, %q) = (%q, %q), want (%q, %q)",
					tt.recordName, tt.zone, host, domain, tt.expectedHost, tt.expectedDomain)
			}
		})
	}
}

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"single asterisk", "*", true},
		{"wildcard prefix", "*.example", true},
		{"normal name", "www", false},
		{"asterisk in middle", "te*st", false},
		{"asterisk at end", "test*", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWildcard(tt.input)
			if result != tt.expected {
				t.Errorf("isWildcard(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    string
	}{
		{"custom description", "My Custom Desc", "My Custom Desc"},
		{"empty description", "", "Managed by Caddy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{EntryDescription: tt.description}
			result := p.getDescription()
			if result != tt.expected {
				t.Errorf("getDescription() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBaseURL(t *testing.T) {
	p := &Provider{Host: "pfsense.local"}
	expected := "https://pfsense.local/api/v2/services/dns_resolver"
	result := p.baseURL()
	if result != expected {
		t.Errorf("baseURL() = %q, want %q", result, expected)
	}
}

func TestGetRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		serverData    []hostOverride
		expectedCount int
		expectedNames []string
	}{
		{
			name: "returns matching records",
			zone: "example.com",
			serverData: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}},
				{ID: 2, Host: "api", Domain: "example.com", IP: []string{"192.168.1.2"}},
				{ID: 3, Host: "other", Domain: "otherdomain.com", IP: []string{"192.168.1.3"}},
			},
			expectedCount: 2,
			expectedNames: []string{"www", "api"},
		},
		{
			name: "returns apex record",
			zone: "my_domain.com",
			serverData: []hostOverride{
				{ID: 1, Host: "my_domain", Domain: "com", IP: []string{"192.168.1.1"}},
			},
			expectedCount: 1,
			expectedNames: []string{"@"},
		},
		{
			name: "returns IPv6 records",
			zone: "example.com",
			serverData: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"2001:db8::1"}},
			},
			expectedCount: 1,
			expectedNames: []string{"www"},
		},
		{
			name: "multi-IP override expands to multiple records",
			zone: "example.com",
			serverData: []hostOverride{
				{ID: 1, Host: "multi", Domain: "example.com", IP: []string{"192.168.1.1", "192.168.1.2"}},
			},
			expectedCount: 2,
			expectedNames: []string{"multi", "multi"},
		},
		{
			name:          "empty response",
			zone:          "example.com",
			serverData:    []hostOverride{},
			expectedCount: 0,
			expectedNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, authMiddleware(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/services/dns_resolver/host_overrides" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method: %s", r.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(listResponse{Code: 200, Status: "ok", Data: tt.serverData})
			}))
			defer server.Close()

			p := newTestProvider(t, server.URL)
			records, err := p.GetRecords(context.Background(), tt.zone)
			if err != nil {
				t.Fatalf("GetRecords() error = %v", err)
			}

			if len(records) != tt.expectedCount {
				t.Errorf("GetRecords() returned %d records, want %d", len(records), tt.expectedCount)
			}

			for i, expectedName := range tt.expectedNames {
				if i >= len(records) {
					break
				}
				rr := records[i].RR()
				if rr.Name != expectedName {
					t.Errorf("record[%d].Name = %q, want %q", i, rr.Name, expectedName)
				}
			}
		})
	}
}

func TestAppendRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		existingHosts []hostOverride
		records       []libdns.Record
		expectPost    bool
		expectPatch   bool
		expectApply   bool
		expectError   bool
		expectedAdded int
	}{
		{
			name:          "append to empty (creates new)",
			zone:          "example.com",
			existingHosts: []hostOverride{},
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectPost:    true,
			expectPatch:   false,
			expectApply:   true,
			expectedAdded: 1,
		},
		{
			name: "append to existing host (patches with added IP)",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}},
			},
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.2")},
			},
			expectPost:    false,
			expectPatch:   true,
			expectApply:   true,
			expectedAdded: 1,
		},
		{
			name:          "skip wildcard",
			zone:          "example.com",
			existingHosts: []hostOverride{},
			records: []libdns.Record{
				libdns.Address{Name: "*", IP: mustParseAddr("192.168.1.1")},
			},
			expectPost:    false,
			expectPatch:   false,
			expectApply:   false,
			expectedAdded: 0,
		},
		{
			name:          "reject non-A/AAAA",
			zone:          "example.com",
			existingHosts: []hostOverride{},
			records: []libdns.Record{
				libdns.TXT{Name: "txt", Text: "some text"},
			},
			expectError:   true,
			expectedAdded: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postCalled := false
			patchCalled := false
			applyCalled := false

			server := newTestServer(t, authMiddleware(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v2/services/dns_resolver/host_overrides" && r.Method == http.MethodGet:
					_ = json.NewEncoder(w).Encode(listResponse{Code: 200, Status: "ok", Data: tt.existingHosts})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPost:
					postCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPatch:
					patchCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/apply" && r.Method == http.MethodPost:
					applyCalled = true
					_ = json.NewEncoder(w).Encode(applyResponse{Code: 200, Status: "ok"})
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			p := newTestProvider(t, server.URL)
			added, err := p.AppendRecords(context.Background(), tt.zone, tt.records)

			if tt.expectError {
				if err == nil {
					t.Error("AppendRecords() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("AppendRecords() error = %v", err)
			}

			if len(added) != tt.expectedAdded {
				t.Errorf("AppendRecords() added %d records, want %d", len(added), tt.expectedAdded)
			}

			if tt.expectPost != postCalled {
				t.Errorf("POST called = %v, want %v", postCalled, tt.expectPost)
			}
			if tt.expectPatch != patchCalled {
				t.Errorf("PATCH called = %v, want %v", patchCalled, tt.expectPatch)
			}
			if tt.expectApply != applyCalled {
				t.Errorf("apply called = %v, want %v", applyCalled, tt.expectApply)
			}
		})
	}
}

func TestSetRecords(t *testing.T) {
	tests := []struct {
		name          string
		zone          string
		existingHosts []hostOverride
		records       []libdns.Record
		expectPost    bool
		expectPatch   bool
		expectApply   bool
	}{
		{
			name:          "create new record",
			zone:          "example.com",
			existingHosts: []hostOverride{},
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectPost:  true,
			expectPatch: false,
			expectApply: true,
		},
		{
			name: "update existing (different IP → PATCH)",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}, Descr: "Managed by Caddy"},
			},
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.2")},
			},
			expectPost:  false,
			expectPatch: true,
			expectApply: true,
		},
		{
			name: "skip identical record",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}, Descr: "Managed by Caddy"},
			},
			records: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectPost:  false,
			expectPatch: false,
			expectApply: false,
		},
		{
			name:          "skip wildcard",
			zone:          "example.com",
			existingHosts: []hostOverride{},
			records: []libdns.Record{
				libdns.Address{Name: "*.sub", IP: mustParseAddr("192.168.1.1")},
			},
			expectPost:  false,
			expectPatch: false,
			expectApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postCalled := false
			patchCalled := false
			applyCalled := false

			server := newTestServer(t, authMiddleware(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v2/services/dns_resolver/host_overrides" && r.Method == http.MethodGet:
					_ = json.NewEncoder(w).Encode(listResponse{Code: 200, Status: "ok", Data: tt.existingHosts})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPost:
					postCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPatch:
					patchCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/apply" && r.Method == http.MethodPost:
					applyCalled = true
					_ = json.NewEncoder(w).Encode(applyResponse{Code: 200, Status: "ok"})
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.SetRecords(context.Background(), tt.zone, tt.records)
			if err != nil {
				t.Fatalf("SetRecords() error = %v", err)
			}

			if tt.expectPost != postCalled {
				t.Errorf("POST called = %v, want %v", postCalled, tt.expectPost)
			}
			if tt.expectPatch != patchCalled {
				t.Errorf("PATCH called = %v, want %v", patchCalled, tt.expectPatch)
			}
			if tt.expectApply != applyCalled {
				t.Errorf("apply called = %v, want %v", applyCalled, tt.expectApply)
			}
		})
	}
}

func TestDeleteRecords(t *testing.T) {
	tests := []struct {
		name            string
		zone            string
		existingHosts   []hostOverride
		recordsToDelete []libdns.Record
		expectDelete    bool
		expectPatch     bool
		expectApply     bool
		expectedDeleted int
	}{
		{
			name: "delete sole IP (→ DELETE whole override)",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectDelete:    true,
			expectPatch:     false,
			expectApply:     true,
			expectedDeleted: 1,
		},
		{
			name: "delete one of multiple IPs (→ PATCH remaining)",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1", "192.168.1.2"}},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "www", IP: mustParseAddr("192.168.1.1")},
			},
			expectDelete:    false,
			expectPatch:     true,
			expectApply:     true,
			expectedDeleted: 1,
		},
		{
			name: "delete non-existing (no-op)",
			zone: "example.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "www", Domain: "example.com", IP: []string{"192.168.1.1"}},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "api", IP: mustParseAddr("192.168.1.2")},
			},
			expectDelete:    false,
			expectPatch:     false,
			expectApply:     false,
			expectedDeleted: 0,
		},
		{
			name: "delete apex @",
			zone: "my_domain.com",
			existingHosts: []hostOverride{
				{ID: 1, Host: "my_domain", Domain: "com", IP: []string{"192.168.1.1"}},
			},
			recordsToDelete: []libdns.Record{
				libdns.Address{Name: "@", IP: mustParseAddr("192.168.1.1")},
			},
			expectDelete:    true,
			expectPatch:     false,
			expectApply:     true,
			expectedDeleted: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deleteCalled := false
			patchCalled := false
			applyCalled := false

			server := newTestServer(t, authMiddleware(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v2/services/dns_resolver/host_overrides" && r.Method == http.MethodGet:
					_ = json.NewEncoder(w).Encode(listResponse{Code: 200, Status: "ok", Data: tt.existingHosts})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodDelete:
					deleteCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/host_override" && r.Method == http.MethodPatch:
					patchCalled = true
					_ = json.NewEncoder(w).Encode(singleResponse{Code: 200, Status: "ok", Data: hostOverride{ID: 1}})
				case r.URL.Path == "/api/v2/services/dns_resolver/apply" && r.Method == http.MethodPost:
					applyCalled = true
					_ = json.NewEncoder(w).Encode(applyResponse{Code: 200, Status: "ok"})
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			p := newTestProvider(t, server.URL)
			deleted, err := p.DeleteRecords(context.Background(), tt.zone, tt.recordsToDelete)
			if err != nil {
				t.Fatalf("DeleteRecords() error = %v", err)
			}

			if len(deleted) != tt.expectedDeleted {
				t.Errorf("DeleteRecords() deleted %d records, want %d", len(deleted), tt.expectedDeleted)
			}

			if tt.expectDelete != deleteCalled {
				t.Errorf("DELETE called = %v, want %v", deleteCalled, tt.expectDelete)
			}
			if tt.expectPatch != patchCalled {
				t.Errorf("PATCH called = %v, want %v", patchCalled, tt.expectPatch)
			}
			if tt.expectApply != applyCalled {
				t.Errorf("apply called = %v, want %v", applyCalled, tt.expectApply)
			}
		})
	}
}

func TestAPIErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
	}{
		{"server error", http.StatusInternalServerError, "Internal Server Error"},
		{"unauthorized", http.StatusUnauthorized, "Unauthorized"},
		{"not found", http.StatusNotFound, "Not Found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.response))
			})
			defer server.Close()

			p := newTestProvider(t, server.URL)
			_, err := p.GetRecords(context.Background(), "example.com")

			if err == nil {
				t.Error("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "API error") {
				t.Errorf("error should contain 'API error', got: %v", err)
			}
		})
	}
}
