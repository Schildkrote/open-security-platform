// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package packs loads jurisdiction policy packs (JSON) that specialize
// default Evaluate rules for US 4A ALPR, GDPR, etc.
package packs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Schildkrote/policy"
)

// Pack is a jurisdiction overlay on the core policy engine.
type Pack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
	// Rules evaluated in order after core defaults can be short-circuited.
	Rules []Rule `json:"rules"`
	// Meta holds human-readable legal notes (not enforced).
	Meta map[string]string `json:"meta,omitempty"`
}

// Rule matches a request subset and forces an outcome.
type Rule struct {
	ID              string   `json:"id"`
	Purposes        []string `json:"purposes,omitempty"` // empty = any
	Roles           []string `json:"roles,omitempty"`
	ObjectTypes     []string `json:"object_types,omitempty"`
	Actions         []string `json:"actions,omitempty"`
	Classifications []string `json:"classifications,omitempty"`
	RequireWarrant  bool     `json:"require_warrant,omitempty"`
	RequireCase     bool     `json:"require_case,omitempty"`
	// When match + requirements satisfied → allow; else outcome below.
	OnFailOutcome string `json:"on_fail_outcome"` // require_warrant|require_case|deny
	OnFailReason  string `json:"on_fail_reason"`
	// If true, a match that passes requirements allows immediately.
	AllowIfOK bool `json:"allow_if_ok,omitempty"`
	// If true, deny even if core would allow.
	ForceDeny  bool   `json:"force_deny,omitempty"`
	DenyReason string `json:"deny_reason,omitempty"`
}

// Load reads a pack JSON file.
func Load(path string) (*Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.ID == "" {
		return nil, fmt.Errorf("pack id required")
	}
	return &p, nil
}

// LoadDir loads all *.json packs from a directory.
func LoadDir(dir string) ([]*Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Pack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Engine evaluates core policy then jurisdiction packs.
type Engine struct {
	Packs []*Pack
}

// NewEngine with packs (may be empty → core only).
func NewEngine(packs ...*Pack) *Engine {
	return &Engine{Packs: packs}
}

// Evaluate runs core policy.Evaluate then pack overlays.
func (e *Engine) Evaluate(r policy.Request) policy.Decision {
	// Normalize like core
	core := policy.Evaluate(r)

	for _, p := range e.Packs {
		if p == nil {
			continue
		}
		for _, rule := range p.Rules {
			if !matchRule(rule, r) {
				continue
			}
			if rule.ForceDeny {
				return policy.Decision{
					Outcome: policy.Deny,
					Reason:  firstNonEmpty(rule.DenyReason, "pack "+p.ID+" rule "+rule.ID),
				}
			}
			ok := true
			reason := ""
			if rule.RequireWarrant && !r.HasWarrant {
				ok = false
				reason = firstNonEmpty(rule.OnFailReason, "warrant required by pack "+p.ID)
			}
			if rule.RequireCase && !r.HasCase {
				ok = false
				if reason == "" {
					reason = firstNonEmpty(rule.OnFailReason, "case required by pack "+p.ID)
				}
			}
			if !ok {
				out := rule.OnFailOutcome
				if out == "" {
					if rule.RequireWarrant {
						out = policy.RequireWarrant
					} else if rule.RequireCase {
						out = policy.RequireCase
					} else {
						out = policy.Deny
					}
				}
				return policy.Decision{Outcome: out, Reason: reason}
			}
			if rule.AllowIfOK {
				return policy.Decision{
					Outcome: policy.Allow,
					Allowed: true,
					Reason:  fmt.Sprintf("pack %s rule %s", p.ID, rule.ID),
				}
			}
		}
	}
	return core
}

func matchRule(rule Rule, r policy.Request) bool {
	purpose := strings.ToLower(strings.TrimSpace(r.Purpose))
	role := strings.ToLower(strings.TrimSpace(r.Role))
	action := strings.ToLower(strings.TrimSpace(r.Action))
	class := strings.ToLower(strings.TrimSpace(r.Classification))
	if class == "" {
		class = "internal"
	}
	if action == "" {
		action = "read"
	}
	if len(rule.Purposes) > 0 && !inFold(rule.Purposes, purpose) {
		return false
	}
	if len(rule.Roles) > 0 && !inFold(rule.Roles, role) {
		return false
	}
	if len(rule.ObjectTypes) > 0 && !inFold(rule.ObjectTypes, r.ObjectType) {
		return false
	}
	if len(rule.Actions) > 0 && !inFold(rule.Actions, action) {
		return false
	}
	if len(rule.Classifications) > 0 && !inFold(rule.Classifications, class) {
		return false
	}
	return true
}

func inFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
