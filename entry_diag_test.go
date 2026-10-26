package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestFetchEntryJS verifies that the proxy serves the SPA's JavaScript bundle
// byte-identical to upstream. Rewriting JS server-side corrupts string literals
// inside the bundle (e.g. "https://x.com" -> the phish host), which breaks SPA
// hydration and causes the server-rendered login form to unmount. The correct
// behaviour -- matching the known-working proxy -- is to pass JS through
// unmodified and let the client-side shim rewrite URLs at runtime.
func TestFetchEntryJS(t *testing.T) {
	cfg := &config{
		phishDomain: "phish.test",
		targetURL:   &url.URL{Scheme: "https", Host: "x.com"},
		origins:     []string{"x.com", "twitter.com", "twimg.com", "pscp.tv"},
		dataDir:     "/tmp/lures_t",
		insecure:    true,
	}
	px := newProxy(cfg, newStore(cfg.dataDir))
	srv := httptest.NewServer(http.HandlerFunc(px.ServeHTTP))
	defer srv.Close()
	client := srv.Client()

	req, _ := http.NewRequest("GET", srv.URL+"/i/flow/login", nil)
	req.Host = "phish.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	re := regexp.MustCompile(`src="(https?://[^"]*entry-client[^"]*)"`)
	m := re.FindSubmatch(html)
	if m == nil {
		t.Fatal("no entry-client src found")
	}
	entryURL := string(m[1])
	t.Logf("entry URL: %s", entryURL)

	// The proxied HTML points at https://phish.test/_xrp/abs.twimg.com/... .
	// Reconstruct the real upstream URL it maps to.
	if !strings.HasPrefix(entryURL, "https://phish.test/_xrp/") {
		t.Fatalf("unexpected entry URL form: %s", entryURL)
	}
	upstreamURL := "https://" + strings.TrimPrefix(entryURL, "https://phish.test/_xrp/")

	// Fetch through the proxy.
	u, _ := url.Parse(entryURL)
	proxyURL := srv.URL + u.RequestURI()
	req2, _ := http.NewRequest("GET", proxyURL, nil)
	req2.Host = "phish.test"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("proxied fetch error: %v", err)
	}
	proxied, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	t.Logf("proxied status=%d ct=%s len=%d", resp2.StatusCode, resp2.Header.Get("Content-Type"), len(proxied))

	// Fetch the real upstream bundle directly for comparison.
	directReq, _ := http.NewRequest("GET", upstreamURL, nil)
	directReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	directResp, err := http.DefaultClient.Do(directReq)
	if err != nil {
		t.Fatalf("upstream fetch error: %v", err)
	}
	direct, _ := io.ReadAll(directResp.Body)
	directResp.Body.Close()
	t.Logf("upstream status=%d len=%d", directResp.StatusCode, len(direct))

	if len(proxied) == 0 {
		t.Fatal("proxied entry JS is empty")
	}
	if string(proxied) != string(direct) {
		t.Errorf("proxied entry JS differs from upstream: proxy %d bytes vs upstream %d bytes", len(proxied), len(direct))
		n := len(proxied)
		if len(direct) < n {
			n = len(direct)
		}
		for i := 0; i < n; i++ {
			if proxied[i] != direct[i] {
				t.Errorf("first diff at byte %d: proxy=%q upstream=%q", i, proxied[i], direct[i])
				break
			}
		}
	}
}
