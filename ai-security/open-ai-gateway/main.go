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

	mux := buildMux(gw, reg, os.Getenv("OSP_AUTH_SECRET"))

	log.Printf("open-ai-gateway listening on %s (upstream=%s)", cfg.Listen, cfg.UpstreamURL)
	log.Fatal(http.ListenAndServe(cfg.Listen, mux))
}

// buildMux wires the gateway's routes. It is a separate function so the routing
// decisions are TESTABLE: main() built this inline, which left main.go at 0%
// coverage and meant nothing pinned the behaviour of /v1/models or the auth gate
// on /admin/tools. Both are security-relevant - one because it must NOT disclose
// the tool registry, the other because it must require a credential.
//
// Only POST carries an inference body. Everything else under /v1/ (GET
// /v1/models, HEAD probes, OPTIONS preflight) has no request body to inspect, so
// routing it into the gateway made it fail with "request body must be a JSON
// object" - a regression introduced by the fail-closed parse. Answered here
// instead.
//
// /v1/models returns an EMPTY list on purpose. This gateway is a
// chat-completions policy point, not a model catalogue, and it must not enumerate
// anything it has not been configured to serve:
//   - it is NOT served from the tool registry, which is a different domain object
//     (Name/Kind/Risk/Endpoint/Scopes) and is already exposed under the
//     authenticated /admin/tools route. Serving it here would mislabel tools as
//     models AND disclose their endpoints and scopes on an unauthenticated path.
//   - it is NOT proxied upstream, which would advertise model names that no
//     policy rule was written against.
//
// Clients that hard-require a non-empty catalogue should be pointed at their
// provider's own endpoint rather than at this gateway.
func buildMux(gw http.Handler, reg *registry.Registry, authSecret string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   []any{},
		})
	})
	mux.Handle("/v1/", gw)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	adminTools := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(reg.List())
		case http.MethodPost:
			var tool registry.Tool
			if err := json.NewDecoder(r.Body).Decode(&tool); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			reg.Register(tool)
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Opt-in shared OIDC/JWT auth (Phase 1): set OSP_AUTH_SECRET to protect the
	// admin API. Empty secret = open (offline default).
	mux.Handle("/admin/tools", auth.Middleware(authSecret, "gateway:admin", adminTools))

	return mux
}
