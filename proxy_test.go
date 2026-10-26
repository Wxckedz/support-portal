package main

import (
	"net/http"
	"testing"
)

// TestIsTextualManifestJSON verifies that the web-app manifest content types
// X/Twitter serve (application/manifest+json and its x- variant) are treated as
// textual so their bodies get rewritten. These manifests hold absolute
// abs.twimg.com icon URLs; without rewriting them the browser fetches the raw
// CDN host and the rewritten CSP blocks the request.
func TestIsTextualManifestJSON(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/manifest+json; charset=utf-8", true},
		{"application/x-web-app-manifest+json", true},
		{"application/json; charset=utf-8", true},
		{"application/ld+json", true},
		{"text/html; charset=utf-8", true},
		{"application/javascript", true},
		{"application/xml", true},
		{"application/x-www-form-urlencoded", true},
		{"image/png", false},
		{"application/octet-stream", false},
		{"application/pdf", false},
		{"text/plain", true},
	}
	for _, c := range cases {
		resp := &http.Response{Header: http.Header{"Content-Type": []string{c.ct}}}
		if got := isTextual(resp); got != c.want {
			t.Errorf("isTextual(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}
