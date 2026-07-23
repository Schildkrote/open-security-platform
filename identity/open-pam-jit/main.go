// Command open-pam-jit runs a self-hosted PAM / JIT access broker.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Schildkrote/open-pam-jit/internal/access"
	"github.com/Schildkrote/open-pam-jit/internal/api"
	"github.com/Schildkrote/open-pam-jit/internal/audit"
	"github.com/Schildkrote/open-pam-jit/internal/bao"
	"github.com/Schildkrote/open-pam-jit/internal/vault"
	"github.com/Schildkrote/platform/auth"
	"github.com/Schildkrote/platform/events"
)

func main() {
	listen := flag.String("listen", ":8085", "listen address")
	passphrase := flag.String("passphrase", "change-me", "vault master passphrase")
	auditFile := flag.String("audit", "audit.jsonl", "audit log file")
	webhooks := flag.String("webhooks", "", "comma-separated integration webhook URLs (opt-in)")
	authSecret := flag.String("auth-secret", "", "shared JWT secret; when set, protects all API routes except /healthz (opt-in)")
	flag.Parse()

	// Secrets backend (Phase 3): OpenBao when BAO_ADDR + BAO_TOKEN are set,
	// otherwise the local encrypted vault (offline default).
	var store access.SecretStore
	if addr, token := os.Getenv("BAO_ADDR"), os.Getenv("BAO_TOKEN"); addr != "" && token != "" {
		store = bao.NewClient(addr, token)
		log.Printf("secrets backend: OpenBao (%s)", addr)
	} else {
		// NOTE: a real deployment uses a random salt stored in a KMS/HSM.
		salt := []byte("open-pam-jit-demo-salt")
		v, err := vault.New(*passphrase, salt)
		if err != nil {
			log.Fatalf("vault: %v", err)
		}
		store = v
	}

	f, err := os.OpenFile(*auditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("audit file: %v", err)
	}
	defer f.Close()
	auditLogger := audit.New(f)

	mgr := access.NewManager(store, auditLogger)
	mgr.AddTarget(access.Target{ID: "prod-db", Name: "Production Database", Type: "database"})
	mgr.AddTarget(access.Target{ID: "prod-ssh", Name: "Production SSH", Type: "ssh"})

	var emitter *events.Emitter
	if *webhooks != "" {
		emitter = events.New("open-pam-jit", splitCSV(*webhooks))
	}

	srv := &api.Server{Mgr: mgr, Audit: auditLogger, Events: emitter}
	routes := srv.Routes()

	// Opt-in shared OIDC/JWT auth (Phase 1). Empty secret = open (offline default);
	// /healthz stays open for liveness probes either way.
	var handler http.Handler = routes
	if *authSecret != "" {
		protected := auth.Middleware(*authSecret, "pam:access", routes)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				routes.ServeHTTP(w, r)
				return
			}
			protected.ServeHTTP(w, r)
		})
	}

	log.Printf("open-pam-jit listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, handler))
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
