// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package actions implements permissioned verbs that mutate the ontology.
package actions

import (
	"fmt"
	"time"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

// Evaluator is the policy decision interface. Core policy and packs.Engine
// both satisfy it; wiring a packs engine puts jurisdiction packs on the
// action hot path.
type Evaluator interface {
	Evaluate(policy.Request) policy.Decision
}

// Engine binds store + policy + audit.
type Engine struct {
	Store *ontology.Store
	Log   *audit.Log
	// Eval is the decision evaluator. nil = core policy.Evaluate (default).
	// Set to packs.NewEngine(packs...) for jurisdiction pack enforcement.
	Eval Evaluator
}

// NewEngine constructs an action engine.
func NewEngine(store *ontology.Store, log *audit.Log) *Engine {
	if log == nil {
		log = audit.New()
	}
	return &Engine{Store: store, Log: log}
}

// Context is the caller context for an action.
type Context struct {
	Actor      string
	Role       string
	Purpose    string
	HasCase    bool
	CaseID     string
	HasWarrant bool
	WarrantID  string
}

// Result is the action outcome.
type Result struct {
	OK       bool            `json:"ok"`
	Name     string          `json:"name"`
	ObjectID string          `json:"object_id,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Policy   policy.Decision `json:"policy"`
}

func (e *Engine) gate(ctx Context, objectType, action string, class string) policy.Decision {
	req := policy.Request{
		Purpose:        ctx.Purpose,
		Role:           ctx.Role,
		Classification: class,
		ObjectType:     objectType,
		Action:         action,
		HasCase:        ctx.HasCase,
		CaseID:         ctx.CaseID,
		HasWarrant:     ctx.HasWarrant,
		WarrantID:      ctx.WarrantID,
	}
	var d policy.Decision
	if e.Eval != nil {
		d = e.Eval.Evaluate(req)
	} else {
		d = policy.Evaluate(req)
	}
	e.Log.Append(audit.Entry{
		Kind:    "policy",
		Actor:   ctx.Actor,
		Purpose: ctx.Purpose,
		Action:  action,
		Outcome: d.Outcome,
		Detail:  map[string]any{"reason": d.Reason, "object_type": objectType},
	})
	return d
}

// OpenCase creates a Case object.
func (e *Engine) OpenCase(ctx Context, caseKey, title string) Result {
	name := "action:open_case"
	d := e.gate(ctx, ontology.TypeCase, name, "restricted")
	if !d.Allowed {
		return Result{Name: name, Reason: d.Reason, Policy: d}
	}
	id := ontology.MakeID(ontology.TypeCase, caseKey)
	_, err := e.Store.UpsertObject(ontology.Object{
		ID:             id,
		Type:           ontology.TypeCase,
		Classification: "restricted",
		Properties: map[string]any{
			"title":  title,
			"status": "open",
			"opened": time.Now().UTC().Format(time.RFC3339),
		},
		Provenance: ontology.Provenance{Source: "actions", Pipeline: "open_case"},
	})
	if err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	e.Log.Append(audit.Entry{Kind: "action", Actor: ctx.Actor, Action: name, ObjectID: id, Outcome: "ok", Purpose: ctx.Purpose})
	return Result{OK: true, Name: name, ObjectID: id, Policy: d}
}

// IssueAlert creates an Alert linked to a subject.
func (e *Engine) IssueAlert(ctx Context, alertKey, subjectID, message string) Result {
	name := "action:issue_alert"
	d := e.gate(ctx, ontology.TypeAlert, name, "internal")
	if !d.Allowed {
		return Result{Name: name, Reason: d.Reason, Policy: d}
	}
	if _, ok := e.Store.Get(subjectID); !ok {
		return Result{Name: name, Reason: "subject missing: " + subjectID, Policy: d}
	}
	id := ontology.MakeID(ontology.TypeAlert, alertKey)
	if _, err := e.Store.UpsertObject(ontology.Object{
		ID:   id,
		Type: ontology.TypeAlert,
		Properties: map[string]any{
			"message": message,
			"status":  "open",
		},
		Provenance: ontology.Provenance{Source: "actions", Pipeline: "issue_alert"},
	}); err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	if _, err := e.Store.AddLink(ontology.Link{
		Type:       ontology.LinkAssociatedWith,
		From:       id,
		To:         subjectID,
		Provenance: ontology.Provenance{Source: "actions"},
	}); err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	e.Log.Append(audit.Entry{Kind: "action", Actor: ctx.Actor, Action: name, ObjectID: id, Outcome: "ok", Purpose: ctx.Purpose})
	return Result{OK: true, Name: name, ObjectID: id, Policy: d}
}

// RequestWarrantPackage attaches a warrant request document stub to a case.
func (e *Engine) RequestWarrantPackage(ctx Context, docKey, caseID, rationale string) Result {
	name := "action:request_warrant_package"
	if ctx.CaseID == "" {
		ctx.CaseID = caseID
		ctx.HasCase = caseID != ""
	}
	d := e.gate(ctx, ontology.TypeDocument, name, "restricted")
	if !d.Allowed {
		return Result{Name: name, Reason: d.Reason, Policy: d}
	}
	if _, ok := e.Store.Get(caseID); !ok {
		return Result{Name: name, Reason: "case missing", Policy: d}
	}
	id := ontology.MakeID(ontology.TypeDocument, docKey)
	if _, err := e.Store.UpsertObject(ontology.Object{
		ID:             id,
		Type:           ontology.TypeDocument,
		Classification: "restricted",
		Properties: map[string]any{
			"kind":      "warrant_package",
			"rationale": rationale,
			"status":    "draft",
		},
		Provenance: ontology.Provenance{Source: "actions"},
	}); err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	if _, err := e.Store.AddLink(ontology.Link{Type: ontology.LinkEvidenceIn, From: id, To: caseID}); err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	e.Log.Append(audit.Entry{Kind: "action", Actor: ctx.Actor, Action: name, ObjectID: id, Outcome: "ok", Purpose: ctx.Purpose})
	return Result{OK: true, Name: name, ObjectID: id, Policy: d}
}

// LinkEvidence links any object into a case.
func (e *Engine) LinkEvidence(ctx Context, objectID, caseID string) Result {
	name := "action:link_evidence"
	d := e.gate(ctx, ontology.TypeCase, name, "restricted")
	if !d.Allowed {
		return Result{Name: name, Reason: d.Reason, Policy: d}
	}
	if _, ok := e.Store.Get(objectID); !ok {
		return Result{Name: name, Reason: fmt.Sprintf("object %s missing", objectID), Policy: d}
	}
	if _, ok := e.Store.Get(caseID); !ok {
		return Result{Name: name, Reason: "case missing", Policy: d}
	}
	l, err := e.Store.AddLink(ontology.Link{Type: ontology.LinkEvidenceIn, From: objectID, To: caseID})
	if err != nil {
		return Result{Name: name, Reason: err.Error(), Policy: d}
	}
	e.Log.Append(audit.Entry{Kind: "action", Actor: ctx.Actor, Action: name, ObjectID: l.ID, Outcome: "ok", Purpose: ctx.Purpose})
	return Result{OK: true, Name: name, ObjectID: l.ID, Policy: d}
}
