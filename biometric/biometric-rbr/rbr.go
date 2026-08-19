// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package rbr implements faceprint embedding + gallery matching for
// consent-gated client protection. The default embedder is a deterministic
// mock (offline). Real ArcFace/SFace weights are user-supplied.
package rbr

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Schildkrote/biometric-audit"
	"github.com/Schildkrote/lawful-basis"
)

// Dim is the mock embedding dimensionality.
const Dim = 32

// DefaultThreshold is the cosine-similarity gate below which no match is
// reported (avoids low-confidence false positives).
const DefaultThreshold = 0.82

// Embedding is a unit-length faceprint vector.
type Embedding []float64

// FaceRecord is one enrolled or probed face (no raw pixels).
type FaceRecord struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id,omitempty"`
	SubjectPseudo string    `json:"subject_pseudo"`
	ImageHash     string    `json:"image_hash"`
	Category      string    `json:"category"`
	Embedding     Embedding `json:"embedding,omitempty"`
}

// Match is one gallery hit above threshold.
type Match struct {
	ProbeID       string  `json:"probe_id"`
	GalleryID     string  `json:"gallery_id"`
	ClientID      string  `json:"client_id"`
	SubjectPseudo string  `json:"subject_pseudo"`
	Score         float64 `json:"score"`
}

// Embedder turns an image hash (or raw bytes handle) into an Embedding.
type Embedder interface {
	Name() string
	Embed(imageHash string) (Embedding, error)
}

// MockEmbedder is a deterministic offline embedder: the embedding is derived
// from SHA-256(imageHash) expanded to Dim floats, then L2-normalised.
type MockEmbedder struct{}

func NewMockEmbedder() *MockEmbedder { return &MockEmbedder{} }
func (m *MockEmbedder) Name() string { return "mock" }

func (m *MockEmbedder) Embed(imageHash string) (Embedding, error) {
	if imageHash == "" {
		return nil, fmt.Errorf("empty image hash")
	}
	sum := sha256.Sum256([]byte(imageHash))
	// Expand to Dim floats using repeated hashing.
	raw := make([]float64, Dim)
	buf := sum[:]
	for i := 0; i < Dim; i++ {
		if i > 0 && i%8 == 0 {
			next := sha256.Sum256(buf)
			buf = next[:]
		}
		off := (i % 8) * 4
		if off+4 > len(buf) {
			off = 0
		}
		u := binary.BigEndian.Uint32(buf[off : off+4])
		raw[i] = float64(u)/float64(^uint32(0)) - 0.5
	}
	return l2normalize(raw), nil
}

func l2normalize(v []float64) Embedding {
	var sum float64
	for _, x := range v {
		sum += x * x
	}
	if sum == 0 {
		return Embedding(v)
	}
	n := math.Sqrt(sum)
	out := make(Embedding, len(v))
	for i, x := range v {
		out[i] = x / n
	}
	return out
}

// Cosine returns the cosine similarity of two unit embeddings.
func Cosine(a, b Embedding) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

// Gallery is an enrolled face set for one or more consenting clients.
type Gallery struct {
	Records []FaceRecord `json:"records"`
	emb     Embedder
	audit   audit.Store
}

// NewGallery returns an empty gallery using emb (defaults to mock).
func NewGallery(emb Embedder) *Gallery {
	if emb == nil {
		emb = NewMockEmbedder()
	}
	return &Gallery{emb: emb}
}

// SetAudit attaches a hash-chained audit store. Every face-touching
// operation (enrol, match, revoke) then appends an entry carrying the
// lawful-basis decision. nil = audit disabled.
func (g *Gallery) SetAudit(s audit.Store) { g.audit = s }

// Audit returns the attached store (nil if not set).
func (g *Gallery) Audit() audit.Store { return g.audit }

// record appends one audit entry; no-op when audit is disabled.
func (g *Gallery) record(action, subjectPseudo, detail string, d basis.Decision) {
	if g.audit == nil {
		return
	}
	_, _ = audit.Record(g.audit, "rbr", action, subjectPseudo, detail, d, true)
}

// LoadJSON loads a gallery file of FaceRecords (embeddings optional).
func LoadJSON(path string, emb Embedder) (*Gallery, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	g := NewGallery(emb)
	if err := json.Unmarshal(b, &g.Records); err != nil {
		return nil, err
	}
	// Ensure embeddings.
	for i := range g.Records {
		if len(g.Records[i].Embedding) == 0 {
			e, err := g.emb.Embed(g.Records[i].ImageHash)
			if err != nil {
				return nil, fmt.Errorf("embed %s: %w", g.Records[i].ID, err)
			}
			g.Records[i].Embedding = e
		}
		if g.Records[i].SubjectPseudo == "" {
			g.Records[i].SubjectPseudo = pseudo(g.Records[i].ClientID)
		}
	}
	return g, nil
}

// Enrol adds a record (embeds if needed). Caller must have passed
// lawful-basis; d is recorded into the audit chain when a store is set.
func (g *Gallery) Enrol(r FaceRecord, d basis.Decision) error {
	if r.ImageHash == "" {
		return fmt.Errorf("image_hash required")
	}
	if len(r.Embedding) == 0 {
		e, err := g.emb.Embed(r.ImageHash)
		if err != nil {
			return err
		}
		r.Embedding = e
	}
	if r.SubjectPseudo == "" {
		r.SubjectPseudo = pseudo(r.ClientID)
	}
	g.Records = append(g.Records, r)
	g.record("enrol", r.SubjectPseudo, "id="+r.ID+" client="+r.ClientID, d)
	return nil
}

// Revoke removes all records for clientID (consent revocation) and records
// the purge into the audit chain.
func (g *Gallery) Revoke(clientID string) int {
	kept := g.Records[:0]
	n := 0
	for _, r := range g.Records {
		if r.ClientID == clientID {
			n++
			continue
		}
		kept = append(kept, r)
	}
	g.Records = kept
	g.record("revoke", pseudo(clientID), "images_purged="+strconv.Itoa(n), basis.Decision{
		Outcome:   basis.Permitted,
		Purpose:   basis.PurposeEnrolment,
		Reason:    "consent revocation purges biometric data",
		DecidedAt: time.Now().UTC(),
	})
	return n
}

// MatchResult is the outcome of matching one probe.
type MatchResult struct {
	Probe   FaceRecord     `json:"probe"`
	Matches []Match        `json:"matches"`
	Basis   basis.Decision `json:"basis"`
	Refused bool           `json:"refused"`
	Reason  string         `json:"reason,omitempty"`
}

// MatchProbe embeds the probe (if needed) and returns gallery hits ≥ threshold.
// hasConsent must be true for the enrolled clients being searched.
func (g *Gallery) MatchProbe(probe FaceRecord, threshold float64, hasConsent bool, category string) MatchResult {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	d := basis.Decide(basis.Request{
		Purpose:       basis.PurposeTargetedSearch,
		Category:      category,
		HasConsent:    hasConsent,
		RetentionDays: 30,
	})
	res := MatchResult{Probe: probe, Basis: d}
	if !d.Allowed() {
		res.Refused = true
		res.Reason = d.Reason
		g.record("match_refused", probeSubjectPseudo(probe), "probe="+probe.ID+" reason="+d.Reason, d)
		return res
	}
	if len(probe.Embedding) == 0 {
		e, err := g.emb.Embed(probe.ImageHash)
		if err != nil {
			res.Refused = true
			res.Reason = err.Error()
			return res
		}
		probe.Embedding = e
		res.Probe = probe
	}
	var hits []Match
	for _, r := range g.Records {
		score := Cosine(probe.Embedding, r.Embedding)
		if score >= threshold {
			hits = append(hits, Match{
				ProbeID:       probe.ID,
				GalleryID:     r.ID,
				ClientID:      r.ClientID,
				SubjectPseudo: r.SubjectPseudo,
				Score:         score,
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	res.Matches = hits
	g.record("match", probeSubjectPseudo(probe),
		"probe="+probe.ID+" n_hits="+strconv.Itoa(len(hits))+" threshold="+strconv.FormatFloat(threshold, 'f', 4, 64), d)
	return res
}

// probeSubjectPseudo returns the probe's subject pseudonym (set if the probe
// is an enrolled client, otherwise the hash of its image).
func probeSubjectPseudo(p FaceRecord) string {
	if p.SubjectPseudo != "" {
		return p.SubjectPseudo
	}
	return pseudo(p.ImageHash)
}

// StreamEvent is one frame from a mock/real stream.
type StreamEvent struct {
	FrameID   string    `json:"frame_id"`
	Timestamp time.Time `json:"timestamp"`
	ImageHash string    `json:"image_hash"`
}

// Stream runs match over a sequence of events (mock stream = slice).
func (g *Gallery) Stream(events []StreamEvent, threshold float64, hasConsent bool) []MatchResult {
	var out []MatchResult
	for _, ev := range events {
		probe := FaceRecord{
			ID:        ev.FrameID,
			ImageHash: ev.ImageHash,
			Category:  basis.CatGeneral,
		}
		out = append(out, g.MatchProbe(probe, threshold, hasConsent, basis.CatGeneral))
	}
	return out
}

func pseudo(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:])
}

// SaveJSON writes the gallery (without forcing embeddings empty).
func (g *Gallery) SaveJSON(path string) error {
	b, err := json.MarshalIndent(g.Records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ParseProbeFile loads a single probe or list of probes.
func ParseProbeFile(path string) ([]FaceRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var one FaceRecord
	if err := json.Unmarshal(b, &one); err == nil && one.ImageHash != "" {
		return []FaceRecord{one}, nil
	}
	var many []FaceRecord
	if err := json.Unmarshal(b, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// NormalizeCategory maps free text to a basis category.
func NormalizeCategory(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return basis.CatGeneral
	}
	return s
}
