// Command open-ai-gateway runs a self-hosted LLM/agent gateway and firewall.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/config"
	"github.com/Schildkrote/open-ai-gateway/internal/mockupstream"
	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/provider"
	"github.com/Schildkrote/open-ai-gateway/internal/proxy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/registry"
	"github.com/Schildkrote/platform/auth"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// LLM provider selection (Phase 3 connectors). Default = offline mock upstream
	// so the gateway runs with zero network access; set OSP_LLM_PROVIDER to
	// openai|anthropic|ollama to proxy to a real provider (credentials via env).
	var authorize func(*http.Request)
	switch name := os.Getenv("OSP_LLM_PROVIDER"); name {
	case "", "mock":
		if cfg.UseMockUpstream {
			srv := httptest.NewServer(mockupstream.Handler())
			cfg.UpstreamURL = srv.URL
			log.Printf("mock upstream listening at %s", srv.URL)
		}
	default:
		p := provider.FromEnv(name, cfg.UpstreamURL)
		cfg.UpstreamURL = p.Endpoint()
		authorize = p.Authorize
		log.Printf("LLM provider %s -> %s", p.Name(), cfg.UpstreamURL)
	}

	engine := &policy.Engine{Default: cfg.DefaultAction, Rules: cfg.Rules}
	if err := engine.Compile(); err != nil {
		log.Fatalf("compile policy: %v", err)
	}

	reg := registry.New()
	for _, t := range cfg.Tools {
		reg.Register(t)
	}

	auditLogger, f, err := audit.OpenFile(cfg.AuditFile)
	if err != nil {
		log.Fatalf("open audit file: %v", err)
	}
	defer f.Close()

	gw := &proxy.Gateway{
		UpstreamURL:    cfg.UpstreamURL,
		Engine:         engine,
		Limiter:        ratelimit.New(cfg.Limits),
		Audit:          auditLogger,
		RedactRequest:  cfg.RedactRequest,
		RedactResponse: cfg.RedactResponse,
		Authorize:      authorize,
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", gw)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	adminTools := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(reg.List())
		case http.MethodPost:
			var t registry.Tool
			if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			reg.Register(t)
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Opt-in shared OIDC/JWT auth (Phase 1): set OSP_AUTH_SECRET to protect the
	// admin API. Empty secret = open (offline default).
	mux.Handle("/admin/tools", auth.Middleware(os.Getenv("OSP_AUTH_SECRET"), "gateway:admin", adminTools))

	log.Printf("open-ai-gateway listening on %s (upstream=%s)", cfg.Listen, cfg.UpstreamURL)
	log.Fatal(http.ListenAndServe(cfg.Listen, mux))
}
