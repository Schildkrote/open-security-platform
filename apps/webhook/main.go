// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/odp-events"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/packs"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8091", "listen address")
	storePath := flag.String("store", "/tmp/odp-webhook-store.json", "ontology store path (loaded if exists, saved on each ingest)")
	token := flag.String("token", "", "optional Bearer token")
	strict := flag.Bool("strict-chain", false, "verify OSP hash chain linkage")
	packsDir := flag.String("packs", "", "dir of jurisdiction pack JSON files (enforces packs on the webhook path)")
	purpose := flag.String("purpose", "investigation", "policy context purpose for webhook ingestion (see policy.Purpose*)")
	role := flag.String("role", "admin", "policy context role for webhook ingestion (see policy.Role*)")
	flag.Parse()

	var store *ontology.Store
	var err error
	if _, err = os.Stat(*storePath); err == nil {
		if strings.HasSuffix(*storePath, ".sqlite") {
			store, err = ontology.LoadSQLite(*storePath)
		} else {
			store, err = ontology.LoadJSON(*storePath)
		}
		if err != nil {
			log.Fatalf("load store: %v", err)
		}
		log.Printf("loaded store %s", *storePath)
	} else {
		store = ontology.NewStore()
	}

	h := events.NewHandler(store, audit.New())
	h.Token = *token
	h.StrictChain = *strict
	h.Pol = events.PolicyContext{Purpose: *purpose, Role: *role}
	if *packsDir != "" {
		loaded, err := packs.LoadDir(*packsDir)
		if err != nil {
			log.Fatalf("load packs: %v", err)
		}
		h.Eval = packs.NewEngine(loaded...)
		log.Printf("loaded %d jurisdiction packs (policy enforced on webhook path)", len(loaded))
	}

	save := func() {
		if strings.HasSuffix(*storePath, ".sqlite") {
			if err := store.SaveSQLite(*storePath); err != nil {
				log.Printf("save sqlite: %v", err)
			}
			return
		}
		if err := store.SaveJSON(*storePath); err != nil {
			log.Printf("save json: %v", err)
		}
	}
	// wrap to persist after each successful POST
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/hooks/osp", func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		if r.Method == http.MethodPost && w.Header().Get("Content-Type") != "" {
			// best-effort save — Handler already wrote status; save regardless if objects grew
		}
		save()
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		log.Printf("ODP OSP webhook listening on http://%s/hooks/osp", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	save()
	fmt.Fprintf(os.Stderr, "saved %s\n", *storePath)
}
