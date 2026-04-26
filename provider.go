// Package pfsense implements a DNS record management client compatible
// with the libdns interfaces for pfSense Unbound host overrides.
//
// This provider manages local DNS host entries via the pfSense REST API v2.
// Only A and AAAA records are supported (no TXT records, so ACME DNS challenges
// cannot be performed with this provider).
package pfsense

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

// Provider facilitates DNS record manipulation with pfSense Unbound.
type Provider struct {
	// Host is the pfSense hostname or IP address (e.g., "pfsense.example.com" or "192.168.1.1")
	Host string `json:"host,omitempty"`
	// APIKey is the pfSense REST API key (sent as x-api-key header)
	APIKey string `json:"api_key,omitempty"`
	// Insecure skips TLS certificate verification (for self-signed certificates)
	Insecure bool `json:"insecure,omitempty"`
	// EntryDescription is set on created host entries (defaults to "Managed by Caddy")
	EntryDescription string `json:"entry_description,omitempty"`
	// Logger is an optional logger. When used with Caddy, set this to ctx.Logger() during Provision.
	Logger *zap.Logger `json:"-"`
}

type hostOverride struct {
	ID     int      `json:"id"`
	Host   string   `json:"host"`
	Domain string   `json:"domain"`
	IP     []string `json:"ip"`
	Descr  string   `json:"descr"`
}

type listResponse struct {
	Code   int            `json:"code"`
	Status string         `json:"status"`
	Data   []hostOverride `json:"data"`
}

type singleResponse struct {
	Code    int          `json:"code"`
	Status  string       `json:"status"`
	Message string       `json:"message,omitempty"`
	Data    hostOverride `json:"data"`
}

type applyResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type createOverrideRequest struct {
	Host   string   `json:"host"`
	Domain string   `json:"domain"`
	IP     []string `json:"ip"`
	Descr  string   `json:"descr"`
}

type updateOverrideRequest struct {
	ID     int      `json:"id"`
	Host   string   `json:"host"`
	Domain string   `json:"domain"`
	IP     []string `json:"ip"`
	Descr  string   `json:"descr"`
}

func (p *Provider) getClient() *http.Client {
	transport := &http.Transport{}
	if p.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func (p *Provider) getDescription() string {
	if p.EntryDescription != "" {
		return p.EntryDescription
	}
	return "Managed by Caddy"
}

func (p *Provider) getLogger() *zap.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return zap.NewNop()
}

func (p *Provider) baseURL() string {
	return "https://" + p.Host + "/api/v2/services/dns_resolver"
}

func (p *Provider) doRequest(ctx context.Context, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("x-api-key", p.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (p *Provider) listHostOverrides(ctx context.Context) ([]hostOverride, error) {
	respBody, err := p.doRequest(ctx, http.MethodGet, p.baseURL()+"/host_overrides", nil)
	if err != nil {
		return nil, err
	}

	var result listResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return result.Data, nil
}

func (p *Provider) createHostOverride(ctx context.Context, host, domain string, ips []string) error {
	reqData := createOverrideRequest{
		Host:   host,
		Domain: domain,
		IP:     ips,
		Descr:  p.getDescription(),
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	respBody, err := p.doRequest(ctx, http.MethodPost, p.baseURL()+"/host_override", strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}

	var result singleResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to create host override: %s", result.Message)
	}

	return nil
}

func (p *Provider) updateHostOverride(ctx context.Context, id int, host, domain string, ips []string) error {
	reqData := updateOverrideRequest{
		ID:     id,
		Host:   host,
		Domain: domain,
		IP:     ips,
		Descr:  p.getDescription(),
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	respBody, err := p.doRequest(ctx, http.MethodPatch, p.baseURL()+"/host_override", strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}

	var result singleResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to update host override: %s", result.Message)
	}

	return nil
}

func (p *Provider) deleteHostOverride(ctx context.Context, id int) error {
	url := fmt.Sprintf("%s/host_override?id=%d", p.baseURL(), id)
	respBody, err := p.doRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	var result singleResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to delete host override: %s", result.Message)
	}

	return nil
}

func (p *Provider) applyChanges(ctx context.Context) error {
	respBody, err := p.doRequest(ctx, http.MethodPost, p.baseURL()+"/apply", nil)
	if err != nil {
		return err
	}

	var result applyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "ok" {
		return fmt.Errorf("failed to apply changes: %s", result.Message)
	}

	return nil
}

// trimZone removes the trailing dot from a zone name.
func trimZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// resolveHostAndDomain handles the special case where name is "@" (zone apex).
// For pfSense, we need to split the zone into host and domain parts.
// e.g., zone "my_domain.com" with name "@" becomes host "my_domain" and domain "com".
func resolveHostAndDomain(name, zone string) (host, domain string) {
	zone = trimZone(zone)
	if name == "@" || name == "" {
		// Zone apex: split the zone at the first dot
		if idx := strings.Index(zone, "."); idx > 0 {
			return zone[:idx], zone[idx+1:]
		}
		// No dot in zone (edge case)
		return zone, ""
	}
	return name, zone
}

// isWildcard checks if the name is a wildcard record.
func isWildcard(name string) bool {
	return name == "*" || strings.HasPrefix(name, "*.")
}

// stringSlicesEqual checks equality of two string slices regardless of order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.getLogger().Debug("getting records", zap.String("zone", zone))

	hosts, err := p.listHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing host overrides: %w", err)
	}

	zone = trimZone(zone)
	var records []libdns.Record

	for _, h := range hosts {
		var name string

		if h.Domain == zone {
			// Normal subdomain: host "www" in domain "example.com"
			name = h.Host
		} else if h.Host+"."+h.Domain == zone {
			// Apex record: host "my_domain" in domain "com" for zone "my_domain.com"
			name = "@"
		} else {
			continue // not part of this zone
		}

		for _, ipStr := range h.IP {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				continue // skip invalid entries
			}
			records = append(records, libdns.Address{
				Name: name,
				IP:   addr,
			})
		}
	}

	p.getLogger().Debug("finished getting records",
		zap.String("zone", zone),
		zap.Int("count", len(records)))

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// If a host override already exists for the given host+domain, the new IP is appended.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("appending records", zap.String("zone", zone), zap.Int("count", len(records)))

	existingHosts, err := p.listHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing host overrides: %w", err)
	}

	existingByKey := make(map[string]*hostOverride)
	for i, h := range existingHosts {
		key := h.Host + ":" + h.Domain
		existingByKey[key] = &existingHosts[i]
	}

	var added []libdns.Record
	needsApply := false

	for _, record := range records {
		rr := record.RR()

		if rr.Type != "A" && rr.Type != "AAAA" {
			return added, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		addr, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return added, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		name := libdns.RelativeName(rr.Name, zone)
		if isWildcard(name) {
			p.getLogger().Warn("skipping wildcard record - pfSense Unbound does not support wildcard host overrides",
				zap.String("record", name),
				zap.String("zone", zone))
			continue
		}

		host, domain := resolveHostAndDomain(name, zone)
		key := host + ":" + domain
		newIP := addr.String()

		if existing, ok := existingByKey[key]; ok {
			newIPs := append(existing.IP, newIP)
			if err := p.updateHostOverride(ctx, existing.ID, host, domain, newIPs); err != nil {
				return added, fmt.Errorf("updating host override %q: %w", name, err)
			}
			existing.IP = newIPs
		} else {
			if err := p.createHostOverride(ctx, host, domain, []string{newIP}); err != nil {
				return added, fmt.Errorf("creating host override %q: %w", name, err)
			}
			newEntry := &hostOverride{Host: host, Domain: domain, IP: []string{newIP}}
			existingByKey[key] = newEntry
		}

		needsApply = true
		added = append(added, libdns.Address{Name: name, IP: addr})
	}

	if needsApply {
		if err := p.applyChanges(ctx); err != nil {
			return added, fmt.Errorf("applying changes: %w", err)
		}
	}

	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("setting records", zap.String("zone", zone), zap.Int("count", len(records)))

	existingHosts, err := p.listHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing host overrides: %w", err)
	}

	existingByKey := make(map[string]hostOverride)
	for _, h := range existingHosts {
		key := h.Host + ":" + h.Domain
		existingByKey[key] = h
	}

	// Group input records by host:domain key, preserving order and accumulating IPs
	type group struct {
		host   string
		domain string
		name   string
		ips    []string
	}
	var groupOrder []string
	groups := make(map[string]*group)

	for _, record := range records {
		rr := record.RR()

		if rr.Type != "A" && rr.Type != "AAAA" {
			return nil, fmt.Errorf("unsupported record type %q: only A and AAAA are supported", rr.Type)
		}

		addr, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", rr.Data, err)
		}

		name := libdns.RelativeName(rr.Name, zone)
		if isWildcard(name) {
			p.getLogger().Warn("skipping wildcard record - pfSense Unbound does not support wildcard host overrides",
				zap.String("record", name),
				zap.String("zone", zone))
			continue
		}

		host, domain := resolveHostAndDomain(name, zone)
		key := host + ":" + domain

		if _, ok := groups[key]; !ok {
			groups[key] = &group{host: host, domain: domain, name: name}
			groupOrder = append(groupOrder, key)
		}
		groups[key].ips = append(groups[key].ips, addr.String())
	}

	var results []libdns.Record
	needsApply := false

	for _, key := range groupOrder {
		g := groups[key]

		if existing, ok := existingByKey[key]; ok {
			if stringSlicesEqual(existing.IP, g.ips) && existing.Descr == p.getDescription() {
				// Already identical, skip
				for _, ipStr := range g.ips {
					if addr, err := netip.ParseAddr(ipStr); err == nil {
						results = append(results, libdns.Address{Name: g.name, IP: addr})
					}
				}
				continue
			}
			// Update existing entry via PATCH
			if err := p.updateHostOverride(ctx, existing.ID, g.host, g.domain, g.ips); err != nil {
				return results, fmt.Errorf("updating host override %q: %w", g.name, err)
			}
		} else {
			// Create new entry
			if err := p.createHostOverride(ctx, g.host, g.domain, g.ips); err != nil {
				return results, fmt.Errorf("creating host override %q: %w", g.name, err)
			}
		}

		needsApply = true
		for _, ipStr := range g.ips {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				results = append(results, libdns.Address{Name: g.name, IP: addr})
			}
		}
	}

	if needsApply {
		if err := p.applyChanges(ctx); err != nil {
			return results, fmt.Errorf("applying changes: %w", err)
		}
	}

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
// If a host override has multiple IPs and only one is deleted, the override is updated with the remaining IPs.
// If all IPs are deleted, the entire host override is removed.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.getLogger().Debug("deleting records", zap.String("zone", zone), zap.Int("count", len(records)))

	existingHosts, err := p.listHostOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing host overrides: %w", err)
	}

	existingByKey := make(map[string]hostOverride)
	for _, h := range existingHosts {
		key := h.Host + ":" + h.Domain
		existingByKey[key] = h
	}

	var deleted []libdns.Record
	needsApply := false

	for _, record := range records {
		rr := record.RR()
		name := libdns.RelativeName(rr.Name, zone)
		host, domain := resolveHostAndDomain(name, zone)
		key := host + ":" + domain

		existing, ok := existingByKey[key]
		if !ok {
			continue // record doesn't exist, nothing to delete
		}

		addr, err := netip.ParseAddr(rr.Data)
		if err != nil {
			continue
		}
		ipToDelete := addr.String()

		// Remove the IP from the existing entry
		var remainingIPs []string
		found := false
		for _, ip := range existing.IP {
			if ip == ipToDelete {
				found = true
			} else {
				remainingIPs = append(remainingIPs, ip)
			}
		}

		if !found {
			continue
		}

		if len(remainingIPs) == 0 {
			// Delete the whole override
			if err := p.deleteHostOverride(ctx, existing.ID); err != nil {
				return deleted, fmt.Errorf("deleting host override %q: %w", name, err)
			}
			delete(existingByKey, key)
		} else {
			// Patch with remaining IPs
			if err := p.updateHostOverride(ctx, existing.ID, host, domain, remainingIPs); err != nil {
				return deleted, fmt.Errorf("updating host override %q: %w", name, err)
			}
			updated := existing
			updated.IP = remainingIPs
			existingByKey[key] = updated
		}

		needsApply = true
		deleted = append(deleted, libdns.Address{Name: name, IP: addr})
	}

	if needsApply {
		if err := p.applyChanges(ctx); err != nil {
			return deleted, fmt.Errorf("applying changes: %w", err)
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
