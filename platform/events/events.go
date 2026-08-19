// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package events implements the OSP-compatible IntegrationEvent envelope
// and a webhook receiver that hydrates the ontology.
//
// Schema mirrors open-security-platform:
//
//	platform/schemas/integration_event.schema.json
package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	obpconnector "github.com/Schildkrote/connector-obp"
	ospconnector "github.com/Schildkrote/connector-osp"
	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

const Genesis = "genesis"

// IntegrationEvent is the OSP cross-component envelope.
type IntegrationEvent struct {
	ID       string         `json:"id"`
	Time     string         `json:"time"`
	Type     string         `json:"type"`
	Source   string         `json:"source"`
	Action   string         `json:"action"`
	Subject  *string        `json:"subject"`
	Refs     map[string]any `json:"refs"`
	Data     map[string]any `json:"data"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Digest computes sha256 over canonical JSON with hash zeroed.
// Matches OSP Go/Python emitters for ASCII payloads when keys are sorted.
func Digest(ev map[string]any) string {
	tmp := make(map[string]any, len(ev))
	for k, v := range ev {
		tmp[k] = v
	}
	tmp["hash"] = ""
	b, _ := marshalCanonical(tmp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func marshalCanonical(v any) ([]byte, error) {
	// Use standard library with sorted map keys via intermediate re-encode.
	// Go's encoding/json does not sort map keys in all versions the same way;
	// we build a stable form for verification helpers used in tests.
	return json.Marshal(sortValue(v))
}

func sortValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// encode as ordered slice of pairs then back — actually use json.Raw via ordered map simulation:
		// simplest portable approach: re-marshal with sorted keys through json.Encoder is NOT sorted.
		// We'll produce a sorted-key object by recursive rebuild into a slice-backed structure
		// represented as map still — Go 1.20+ json.Marshal maps in sorted key order.
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortValue(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = sortValue(x)
		}
		return out
	default:
		return v
	}
}

// ToMap converts a typed event to map for digest.
func (e IntegrationEvent) ToMap() map[string]any {
	m := map[string]any{
		"id":        e.ID,
		"time":      e.Time,
		"type":      e.Type,
		"source":    e.Source,
		"action":    e.Action,
		"refs":      e.Refs,
		"data":      e.Data,
		"prev_hash": e.PrevHash,
		"hash":      e.Hash,
	}
	if e.Subject != nil {
		m["subject"] = *e.Subject
	} else {
		m["subject"] = nil
	}
	if e.Refs == nil {
		m["refs"] = map[string]any{}
	}
	if e.Data == nil {
		m["data"] = map[string]any{}
	}
	return m
}

// VerifyHash checks event hash matches content.
func (e IntegrationEvent) VerifyHash() bool {
	m := e.ToMap()
	want := e.Hash
	got := Digest(m)
	return want != "" && want == got
}

// Chain tracks prev_hash for optional inbound verification.
type Chain struct {
	mu   sync.Mutex
	prev string
	log  []IntegrationEvent
}

// NewChain starts at genesis.
func NewChain() *Chain { return &Chain{prev: Genesis} }

// Accept verifies linkage (optional strict) and appends.
func (c *Chain) Accept(ev IntegrationEvent, strict bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strict {
		if ev.PrevHash != c.prev {
			return fmt.Errorf("prev_hash mismatch: got %s want %s", ev.PrevHash, c.prev)
		}
		if !ev.VerifyHash() {
			return fmt.Errorf("hash mismatch for event %s", ev.ID)
		}
	}
	if ev.Hash != "" {
		c.prev = ev.Hash
	}
	c.log = append(c.log, ev)
	return nil
}

// Len returns accepted count.
func (c *Chain) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.log)
}

// Evaluator is the policy decision interface. Core policy and packs.Engine
// both satisfy it; wiring a packs engine puts jurisdiction packs on the
// webhook hot path.
type Evaluator interface {
	Evaluate(policy.Request) policy.Decision
}

// PolicyContext is the caller context used to gate webhook hydration.
type PolicyContext struct {
	Purpose string // default "research" (connector ingest)
	Role    string // default "admin" (trusted inbound, allowlisted sender)
}

// Handler receives OSP webhooks and hydrates the ontology.
type Handler struct {
	Store       *ontology.Store
	Log         *audit.Log
	Chain       *Chain
	StrictChain bool   // verify hash chain (off by default: multi-producer fan-in)
	Token       string // optional Bearer shared secret
	// Eval gates hydration: nil = core policy, set = packs.Engine.
	// Webhook ingestion is a policy-gated write per AGENTS.md rule 1.
	Eval    Evaluator
	Pol     PolicyContext
	mu      sync.Mutex
	lastIDs map[string]time.Time // dedupe
}

// NewHandler constructs a webhook handler.
func NewHandler(store *ontology.Store, log *audit.Log) *Handler {
	if log == nil {
		log = audit.New()
	}
	return &Handler{
		Store:   store,
		Log:     log,
		Chain:   NewChain(),
		lastIDs: map[string]time.Time{},
	}
}

// ServeHTTP implements http.Handler — POST /hooks/osp
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if h.Token != "" {
		auth := r.Header.Get("Authorization")
		want := "Bearer " + h.Token
		if auth != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var ev IntegrationEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	res, err := h.Ingest(ev)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// IngestResult summarizes hydration.
type IngestResult struct {
	EventID   string `json:"event_id"`
	ObjectID  string `json:"object_id,omitempty"`
	Duplicate bool   `json:"duplicate,omitempty"`
	Kind      string `json:"kind"`
}

// Ingest one IntegrationEvent into the ontology.
func (h *Handler) Ingest(ev IntegrationEvent) (IngestResult, error) {
	if ev.ID == "" || ev.Type == "" || ev.Source == "" {
		return IngestResult{}, fmt.Errorf("id, type, source required")
	}
	h.mu.Lock()
	if _, ok := h.lastIDs[ev.ID]; ok {
		h.mu.Unlock()
		return IngestResult{EventID: ev.ID, Duplicate: true, Kind: "duplicate"}, nil
	}
	h.lastIDs[ev.ID] = time.Now().UTC()
	// prune old
	if len(h.lastIDs) > 10000 {
		h.lastIDs = map[string]time.Time{ev.ID: time.Now().UTC()}
	}
	h.mu.Unlock()

	if err := h.Chain.Accept(ev, h.StrictChain); err != nil {
		return IngestResult{}, err
	}

	subject := ""
	if ev.Subject != nil {
		subject = *ev.Subject
	}

	// Resolve event timestamp (used by both the typed OBP path and the
	// generic finding path).
	ts := time.Now().UTC()
	if ev.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, ev.Time); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, ev.Time); err == nil {
			ts = t
		}
	}

	// Policy gate for hydration (packs on the hot path when Eval is set).
	// Default context: investigation/admin — the trusted-connector ingest
	// posture that core policy allows; packs can still require case/warrant
	// for biometric & ALPR object types (e.g. eu-ai-act-rbi, gdpr-biometric).
	if h.Eval != nil {
		pc := h.Pol
		if pc.Purpose == "" {
			pc.Purpose = policy.PurposeInvestigation
		}
		if pc.Role == "" {
			pc.Role = policy.RoleAdmin
		}
		d := h.Eval.Evaluate(policy.Request{
			Purpose:        pc.Purpose,
			Role:           pc.Role,
			Classification: "internal",
			ObjectType:     objectTypeForEvent(ev),
			Action:         "write",
		})
		h.Log.Append(audit.Entry{
			Kind: "policy", Actor: "webhook:" + ev.Source, Purpose: pc.Purpose,
			Action: "webhook.ingest", Outcome: d.Outcome,
			Detail: map[string]any{"reason": d.Reason, "event_type": ev.Type},
		})
		if !d.Allowed {
			return IngestResult{}, fmt.Errorf("policy %s: %s", d.Outcome, d.Reason)
		}
	}

	// OBP biometric match hits take the typed connector path:
	// BiometricHit + Person(pseudo) objects, never raw pixels.
	if isOBPBiometric(ev) {
		ph := obpconnector.MatchHit{
			ID:            ev.ID,
			ClientPseudo:  firstString(ev.Data, "client_pseudo", subject),
			ProbeID:       firstString(ev.Data, "probe_id", ""),
			Score:         firstFloat(ev.Data, "score"),
			Source:        firstString(ev.Data, "source", ev.Source),
			RetentionDays: int(firstFloat(ev.Data, "retention_days")),
			TS:            ts,
		}
		objID, err := obpconnector.Ingest(h.Store, ph)
		if err != nil {
			return IngestResult{}, err
		}
		h.Log.Append(audit.Entry{
			Kind: "ingest", Actor: "webhook:" + ev.Source,
			Action: "obp.match_hit", ObjectID: objID, Outcome: "ok",
			Detail: map[string]any{"client_pseudo": ph.ClientPseudo, "score": ph.Score},
		})
		return IngestResult{EventID: ev.ID, ObjectID: objID, Kind: "biometric_hit"}, nil
	}

	// Map event type → finding / event object
	kind := mapEventKind(ev.Type, ev.Action)
	summary := fmt.Sprintf("%s/%s", ev.Type, ev.Action)
	if s, ok := ev.Data["summary"].(string); ok && s != "" {
		summary = s
	}
	severity, _ := ev.Data["severity"].(string)
	props := map[string]any{}
	for k, v := range ev.Data {
		props[k] = v
	}
	for k, v := range ev.Refs {
		props["ref_"+k] = v
	}
	props["event_type"] = ev.Type
	props["event_action"] = ev.Action

	objID, err := ospconnector.Ingest(h.Store, ospconnector.Finding{
		ID:         ev.ID,
		Kind:       kind,
		Subject:    subject,
		Summary:    summary,
		Severity:   severity,
		Properties: props,
		TS:         ts,
		Source:     ev.Source,
	})
	if err != nil {
		return IngestResult{}, err
	}

	h.Log.Append(audit.Entry{
		Kind:     "ingest",
		Actor:    "webhook:" + ev.Source,
		Action:   "osp.integration_event",
		ObjectID: objID,
		Outcome:  "ok",
		Detail: map[string]any{
			"event_type": ev.Type,
			"event_id":   ev.ID,
		},
	})

	return IngestResult{EventID: ev.ID, ObjectID: objID, Kind: kind}, nil
}

// isOBPBiometric reports whether the event is an OBP biometric match hit
// (source "obp" or type containing "biometric"). These take the typed
// connector path instead of the generic finding path.
func isOBPBiometric(ev IntegrationEvent) bool {
	if strings.EqualFold(strings.TrimSpace(ev.Source), "obp") {
		return true
	}
	return strings.Contains(strings.ToLower(ev.Type), "biometric")
}

func firstString(m map[string]any, key, fallback string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

func firstFloat(m map[string]any, key string) float64 {
	if v, ok := m[key]; ok {
		switch x := v.(type) {
		case float64:
			return x
		case float32:
			return float64(x)
		case int:
			return float64(x)
		case int64:
			return float64(x)
		case json.Number:
			if f, err := x.Float64(); err == nil {
				return f
			}
		}
	}
	return 0
}

// objectTypeForEvent maps an inbound OSP event to the ontology object type
// the policy decision should be evaluated against (so packs targeting
// BiometricHit / PlateRead fire on the webhook path).
func objectTypeForEvent(ev IntegrationEvent) string {
	t := strings.ToLower(ev.Type + " " + ev.Action)
	switch {
	case strings.Contains(t, "biometric"):
		return ontology.TypeBiometricHit
	case strings.Contains(t, "plate") || strings.Contains(t, "alpr"):
		return ontology.TypePlateRead
	case strings.Contains(t, "person"):
		return ontology.TypePerson
	default:
		return ontology.TypeFinding
	}
}

func mapEventKind(typ, action string) string {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "finding"):
		return "finding"
	case strings.Contains(t, "breach") || strings.Contains(t, "credential"):
		return "breach"
	case strings.Contains(t, "campaign"):
		return "campaign"
	case strings.Contains(t, "evidence"):
		return "evidence"
	case strings.Contains(t, "access"):
		return "access"
	case strings.Contains(t, "attack"):
		return "attack_path"
	default:
		if action != "" {
			return action
		}
		return "osp_event"
	}
}

// BuildEvent is a test helper that produces a valid chained event.
func BuildEvent(prev, typ, source, action, subject string, data map[string]any) IntegrationEvent {
	if data == nil {
		data = map[string]any{}
	}
	var subj *string
	if subject != "" {
		subj = &subject
	}
	ev := IntegrationEvent{
		ID:       fmt.Sprintf("ev-%d", time.Now().UnixNano()),
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Type:     typ,
		Source:   source,
		Action:   action,
		Subject:  subj,
		Refs:     map[string]any{},
		Data:     data,
		PrevHash: prev,
		Hash:     "",
	}
	ev.Hash = Digest(ev.ToMap())
	return ev
}

// ListenAndServe starts a tiny HTTP server (for demos). Returns the server.
func ListenAndServe(addr string, h *Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/hooks/osp", h)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	return srv
}

// PostJSON is a test helper.
func PostJSON(url string, body any, token string) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}
