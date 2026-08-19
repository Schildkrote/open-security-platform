// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package aip exports Ontology ContextBundles for LLM/agent consumption.
// Bundles are typed, policy-filtered, and redacted — agents never see raw
// biometrics or secret fields unless policy allows.
package aip

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

// ContextBundle is durable agent memory rooted in the ontology.
type ContextBundle struct {
	Version    string            `json:"version"`
	Generated  time.Time         `json:"generated_at"`
	Purpose    string            `json:"purpose"`
	Role       string            `json:"role"`
	RootID     string            `json:"root_id"`
	Depth      int               `json:"depth"`
	PolicyNote string            `json:"policy_note,omitempty"`
	Objects    []BundleObject    `json:"objects"`
	Links      []BundleLink      `json:"links"`
	Redacted   int               `json:"redacted_count"`
	Denied     int               `json:"denied_count"`
	Hints      map[string]string `json:"hints,omitempty"`
}

// BundleObject is a redacted object view.
type BundleObject struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	Classification string         `json:"classification"`
	Properties     map[string]any `json:"properties"`
	Provenance     string         `json:"provenance_source,omitempty"`
}

// BundleLink is a simplified edge.
type BundleLink struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

// ExportOptions control bundle generation.
type ExportOptions struct {
	RootID       string
	Depth        int
	Purpose      string
	Role         string
	HasCase      bool
	CaseID       string
	HasWarrant   bool
	WarrantID    string
	MaxObjects   int
	IncludeHints bool
	// RedactKeys strips these property keys always.
	RedactKeys []string
}

// DefaultRedactKeys are never exported to agents.
var DefaultRedactKeys = []string{
	"embedding", "raw_image", "image_bytes", "face_crop", "ssn", "password",
	"secret", "credential", "rtsp_url", "token", "api_key",
}

// Export builds a ContextBundle from the store under policy.
func Export(store *ontology.Store, opt ExportOptions) (*ContextBundle, error) {
	if store == nil {
		return nil, fmt.Errorf("store required")
	}
	if opt.RootID == "" {
		return nil, fmt.Errorf("root_id required")
	}
	if opt.Depth < 0 {
		opt.Depth = 0
	}
	if opt.Depth > 6 {
		opt.Depth = 6
	}
	if opt.Purpose == "" {
		opt.Purpose = policy.PurposeInvestigation
	}
	if opt.Role == "" {
		opt.Role = policy.RoleAgent
	}
	if opt.MaxObjects <= 0 {
		opt.MaxObjects = 100
	}
	redact := map[string]bool{}
	for _, k := range DefaultRedactKeys {
		redact[strings.ToLower(k)] = true
	}
	for _, k := range opt.RedactKeys {
		redact[strings.ToLower(k)] = true
	}

	objs, links := store.Expand(opt.RootID, opt.Depth)
	b := &ContextBundle{
		Version:   "1.0",
		Generated: time.Now().UTC(),
		Purpose:   opt.Purpose,
		Role:      opt.Role,
		RootID:    opt.RootID,
		Depth:     opt.Depth,
		Objects:   []BundleObject{},
		Links:     []BundleLink{},
	}

	allowedIDs := map[string]bool{}
	for _, o := range objs {
		if o == nil {
			continue
		}
		if len(b.Objects) >= opt.MaxObjects {
			break
		}
		d := policy.Evaluate(policy.Request{
			Purpose:        opt.Purpose,
			Role:           opt.Role,
			Classification: o.Classification,
			ObjectType:     o.Type,
			Action:         "read",
			HasCase:        opt.HasCase,
			CaseID:         opt.CaseID,
			HasWarrant:     opt.HasWarrant,
			WarrantID:      opt.WarrantID,
		})
		if !d.Allowed {
			b.Denied++
			continue
		}
		props, nRed := redactProps(o.Properties, redact)
		b.Redacted += nRed
		b.Objects = append(b.Objects, BundleObject{
			ID:             o.ID,
			Type:           o.Type,
			Classification: o.Classification,
			Properties:     props,
			Provenance:     o.Provenance.Source,
		})
		allowedIDs[o.ID] = true
	}

	for _, l := range links {
		if l == nil {
			continue
		}
		if !allowedIDs[l.From] || !allowedIDs[l.To] {
			continue
		}
		b.Links = append(b.Links, BundleLink{Type: l.Type, From: l.From, To: l.To})
	}
	sort.Slice(b.Objects, func(i, j int) bool { return b.Objects[i].ID < b.Objects[j].ID })
	sort.Slice(b.Links, func(i, j int) bool {
		if b.Links[i].From == b.Links[j].From {
			return b.Links[i].To < b.Links[j].To
		}
		return b.Links[i].From < b.Links[j].From
	})

	if opt.IncludeHints {
		b.Hints = map[string]string{
			"usage":             "Treat objects/links as ground truth for this purpose. Do not invent ids. Propose actions; do not execute.",
			"actions_available": "open_case, issue_alert, request_warrant_package, link_evidence (human/policy gated)",
			"memory":            "Episodic: links+timestamps; Semantic: object types; Procedural: propose only listed actions",
		}
	}
	if b.Denied > 0 {
		b.PolicyNote = fmt.Sprintf("%d objects omitted by policy", b.Denied)
	}
	return b, nil
}

func redactProps(in map[string]any, deny map[string]bool) (map[string]any, int) {
	out := map[string]any{}
	n := 0
	for k, v := range in {
		if deny[strings.ToLower(k)] {
			n++
			continue
		}
		// strip nested secrets lightly
		if s, ok := v.(string); ok && len(s) > 500 {
			out[k] = s[:500] + "…"
			n++
			continue
		}
		out[k] = v
	}
	return out, n
}

// WriteJSON writes the bundle to path.
func WriteJSON(path string, b *ContextBundle) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// Markdown renders a compact agent-facing brief.
func (b *ContextBundle) Markdown() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# ContextBundle `%s`\n\n", b.RootID)
	fmt.Fprintf(&sb, "- purpose: `%s` · role: `%s` · depth: %d\n", b.Purpose, b.Role, b.Depth)
	fmt.Fprintf(&sb, "- objects: %d · links: %d · redacted_fields: %d · denied: %d\n\n",
		len(b.Objects), len(b.Links), b.Redacted, b.Denied)
	if b.PolicyNote != "" {
		fmt.Fprintf(&sb, "> %s\n\n", b.PolicyNote)
	}
	sb.WriteString("## Objects\n\n")
	for _, o := range b.Objects {
		fmt.Fprintf(&sb, "### %s (%s)\n", o.ID, o.Type)
		for k, v := range o.Properties {
			fmt.Fprintf(&sb, "- %s: %v\n", k, v)
		}
		sb.WriteByte('\n')
	}
	sb.WriteString("## Links\n\n")
	for _, l := range b.Links {
		fmt.Fprintf(&sb, "- %s --%s--> %s\n", l.From, l.Type, l.To)
	}
	return sb.String()
}
