// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package alpr ingests vehicle plate events and evaluates hotlists.
// Flock-like *capability* for agency-owned sensors under LE lawful basis —
// not a civilian mass-surveillance network.
package alpr

import (
	"fmt"
	"strings"
	"time"

	"github.com/Schildkrote/odp-audit"
	"github.com/Schildkrote/ontology"
	"github.com/Schildkrote/policy"
)

// PlateEvent is one observation from an ALPR sensor.
type PlateEvent struct {
	EventID    string    `json:"event_id"`
	Plate      string    `json:"plate"`
	State      string    `json:"state,omitempty"`
	CameraID   string    `json:"camera_id"`
	LocationID string    `json:"location_id,omitempty"`
	TS         time.Time `json:"ts"`
	Make       string    `json:"make,omitempty"`
	Model      string    `json:"model,omitempty"`
	Color      string    `json:"color,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
	// VehicleFingerprint optional attrs (bumper sticker, damage) — Flock-style
	Attrs map[string]string `json:"attrs,omitempty"`
}

// HotlistEntry is a plate of interest.
type HotlistEntry struct {
	Plate    string `json:"plate"`
	Reason   string `json:"reason"`
	CaseID   string `json:"case_id,omitempty"`
	Source   string `json:"source,omitempty"` // NCIC mock, local, etc.
	Priority int    `json:"priority,omitempty"`
}

// Hotlist is an in-memory plate index.
type Hotlist struct {
	byPlate map[string]HotlistEntry
}

// NewHotlist builds from entries.
func NewHotlist(entries []HotlistEntry) *Hotlist {
	h := &Hotlist{byPlate: map[string]HotlistEntry{}}
	for _, e := range entries {
		h.byPlate[normalizePlate(e.Plate)] = e
	}
	return h
}

func normalizePlate(p string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(p), " ", ""))
}

// Match checks a plate.
func (h *Hotlist) Match(plate string) (HotlistEntry, bool) {
	e, ok := h.byPlate[normalizePlate(plate)]
	return e, ok
}

// Evaluator is the policy decision interface. Core policy and packs.Engine
// both satisfy it; wiring a packs engine puts jurisdiction packs on the
// ALPR hot path (see AGENTS.md scaffold-honesty note).
type Evaluator interface {
	Evaluate(policy.Request) policy.Decision
}

// Ingestor writes plate events into the ontology under policy.
type Ingestor struct {
	Store   *ontology.Store
	Log     *audit.Log
	Hotlist *Hotlist
	// Eval is the decision evaluator. nil = core policy.Evaluate (default).
	// Set to packs.NewEngine(packs...) for jurisdiction pack enforcement.
	Eval Evaluator
}

// evaluate runs the configured evaluator (core policy when Eval is nil).
func (in *Ingestor) evaluate(r policy.Request) policy.Decision {
	if in.Eval != nil {
		return in.Eval.Evaluate(r)
	}
	return policy.Evaluate(r)
}

// IngestContext is LE caller context.
type IngestContext struct {
	Actor      string
	Role       string
	Purpose    string // patrol_alert | investigation | pattern_of_life
	HasCase    bool
	CaseID     string
	HasWarrant bool
	WarrantID  string
}

// IngestResult summarizes one event.
type IngestResult struct {
	PlateReadID string          `json:"plate_read_id"`
	VehicleID   string          `json:"vehicle_id"`
	HotHit      bool            `json:"hot_hit"`
	HotReason   string          `json:"hot_reason,omitempty"`
	AlertID     string          `json:"alert_id,omitempty"`
	Policy      policy.Decision `json:"policy"`
	Error       string          `json:"error,omitempty"`
}

// Ingest one plate event (live path uses PurposePatrolAlert).
func (in *Ingestor) Ingest(ctx IngestContext, ev PlateEvent) IngestResult {
	if in.Log == nil {
		in.Log = audit.New()
	}
	if ctx.Purpose == "" {
		ctx.Purpose = policy.PurposePatrolAlert
	}
	if ctx.Role == "" {
		ctx.Role = policy.RoleOfficer
	}
	d := in.evaluate(policy.Request{
		Purpose:        ctx.Purpose,
		Role:           ctx.Role,
		Classification: "internal",
		ObjectType:     ontology.TypePlateRead,
		Action:         "read",
		HasCase:        ctx.HasCase,
		CaseID:         ctx.CaseID,
		HasWarrant:     ctx.HasWarrant,
		WarrantID:      ctx.WarrantID,
	})
	in.Log.Append(audit.Entry{
		Kind: "policy", Actor: ctx.Actor, Purpose: ctx.Purpose,
		Action: "alpr.ingest", Outcome: d.Outcome,
		Detail: map[string]any{"reason": d.Reason, "plate": ev.Plate},
	})
	if !d.Allowed {
		return IngestResult{Policy: d, Error: d.Reason}
	}

	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	plate := normalizePlate(ev.Plate)
	if plate == "" {
		return IngestResult{Policy: d, Error: "empty plate"}
	}
	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("%s-%d", plate, ev.TS.UnixNano())
	}

	// Ensure sensor
	sensorID := ontology.MakeID(ontology.TypeSensor, ev.CameraID)
	if ev.CameraID != "" {
		_, _ = in.Store.UpsertObject(ontology.Object{
			ID:   sensorID,
			Type: ontology.TypeSensor,
			Properties: map[string]any{
				"kind": "alpr_camera",
				"id":   ev.CameraID,
			},
			Provenance: ontology.Provenance{Source: "alpr", ExternalID: ev.CameraID},
		})
	}

	vehicleID := ontology.MakeID(ontology.TypeVehicle, plate)
	props := map[string]any{"plate": plate}
	if ev.State != "" {
		props["state"] = ev.State
	}
	if ev.Make != "" {
		props["make"] = ev.Make
	}
	if ev.Model != "" {
		props["model"] = ev.Model
	}
	if ev.Color != "" {
		props["color"] = ev.Color
	}
	for k, v := range ev.Attrs {
		props["attr_"+k] = v
	}
	if _, err := in.Store.UpsertObject(ontology.Object{
		ID: vehicleID, Type: ontology.TypeVehicle, Properties: props,
		Provenance: ontology.Provenance{Source: "alpr", ExternalID: plate},
	}); err != nil {
		return IngestResult{Policy: d, Error: err.Error()}
	}

	readID := ontology.MakeID(ontology.TypePlateRead, ev.EventID)
	readProps := map[string]any{
		"plate":      plate,
		"ts":         ev.TS.UTC().Format(time.RFC3339Nano),
		"camera_id":  ev.CameraID,
		"confidence": ev.Confidence,
	}
	if _, err := in.Store.UpsertObject(ontology.Object{
		ID: readID, Type: ontology.TypePlateRead, Properties: readProps,
		Provenance: ontology.Provenance{Source: "alpr", ExternalID: ev.EventID, Pipeline: "live"},
	}); err != nil {
		return IngestResult{Policy: d, Error: err.Error()}
	}
	_, _ = in.Store.AddLink(ontology.Link{Type: ontology.LinkAssociatedWith, From: readID, To: vehicleID, Provenance: ontology.Provenance{Source: "alpr"}})
	if ev.CameraID != "" {
		_, _ = in.Store.AddLink(ontology.Link{Type: ontology.LinkCapturedBy, From: readID, To: sensorID, Provenance: ontology.Provenance{Source: "alpr"}})
	}
	if ev.LocationID != "" {
		locID := ev.LocationID
		if !strings.Contains(locID, ":") {
			locID = ontology.MakeID(ontology.TypeLocation, ev.LocationID)
		}
		_, _ = in.Store.UpsertObject(ontology.Object{ID: locID, Type: ontology.TypeLocation, Provenance: ontology.Provenance{Source: "alpr"}})
		_, _ = in.Store.AddLink(ontology.Link{Type: ontology.LinkObservedAt, From: vehicleID, To: locID, Provenance: ontology.Provenance{Source: "alpr"}})
	}

	res := IngestResult{PlateReadID: readID, VehicleID: vehicleID, Policy: d}
	if in.Hotlist != nil {
		if hit, ok := in.Hotlist.Match(plate); ok {
			res.HotHit = true
			res.HotReason = hit.Reason
			_, _ = in.Store.AddLink(ontology.Link{
				Type: ontology.LinkMatchedHotlist, From: readID, To: vehicleID,
				Properties: map[string]any{"reason": hit.Reason, "source": hit.Source, "priority": hit.Priority},
				Provenance: ontology.Provenance{Source: "alpr"},
			})
			alertID := ontology.MakeID(ontology.TypeAlert, "hot-"+ev.EventID)
			_, _ = in.Store.UpsertObject(ontology.Object{
				ID: alertID, Type: ontology.TypeAlert,
				Properties: map[string]any{
					"message": fmt.Sprintf("HOTLIST %s: %s", plate, hit.Reason),
					"status":  "open",
					"plate":   plate,
				},
				Provenance: ontology.Provenance{Source: "alpr", Pipeline: "hotlist"},
			})
			_, _ = in.Store.AddLink(ontology.Link{Type: ontology.LinkAssociatedWith, From: alertID, To: vehicleID})
			res.AlertID = alertID
			if hit.CaseID != "" {
				caseID := hit.CaseID
				if !strings.Contains(caseID, ":") {
					caseID = ontology.MakeID(ontology.TypeCase, hit.CaseID)
				}
				if _, ok := in.Store.Get(caseID); ok {
					_, _ = in.Store.AddLink(ontology.Link{Type: ontology.LinkEvidenceIn, From: readID, To: caseID})
				}
			}
		}
	}
	in.Log.Append(audit.Entry{
		Kind: "ingest", Actor: ctx.Actor, Purpose: ctx.Purpose,
		ObjectID: readID, Action: "alpr.ingest", Outcome: "ok",
		Detail: map[string]any{"hot_hit": res.HotHit, "plate": plate},
	})
	return res
}

// QueryHistorical returns plate reads for a plate — requires warrant-friendly purpose.
func (in *Ingestor) QueryHistorical(ctx IngestContext, plate string) ([]*ontology.Object, policy.Decision, error) {
	if ctx.Purpose == "" {
		ctx.Purpose = policy.PurposePatternOfLife
	}
	d := in.evaluate(policy.Request{
		Purpose:    ctx.Purpose,
		Role:       ctx.Role,
		ObjectType: ontology.TypePlateRead,
		Action:     "query_historical",
		HasCase:    ctx.HasCase,
		CaseID:     ctx.CaseID,
		HasWarrant: ctx.HasWarrant,
		WarrantID:  ctx.WarrantID,
	})
	in.Log.Append(audit.Entry{
		Kind: "policy", Actor: ctx.Actor, Purpose: ctx.Purpose,
		Action: "alpr.query_historical", Outcome: d.Outcome,
		Detail: map[string]any{"reason": d.Reason, "plate": plate},
	})
	if !d.Allowed {
		return nil, d, fmt.Errorf("policy %s: %s", d.Outcome, d.Reason)
	}
	plate = normalizePlate(plate)
	all := in.Store.QueryObjects(ontology.Query{Type: ontology.TypePlateRead})
	var out []*ontology.Object
	for _, o := range all {
		if p, _ := o.Properties["plate"].(string); normalizePlate(p) == plate {
			out = append(out, o)
		}
	}
	return out, d, nil
}

// MockStream returns demo events for tests/integration.
func MockStream() []PlateEvent {
	now := time.Now().UTC()
	return []PlateEvent{
		{EventID: "e1", Plate: "ABC123", CameraID: "cam-north", LocationID: "gate-n", TS: now.Add(-2 * time.Minute), Color: "black", Confidence: 0.94},
		{EventID: "e2", Plate: "ZZZ999", CameraID: "cam-south", LocationID: "gate-s", TS: now.Add(-1 * time.Minute), Color: "white", Confidence: 0.91},
		{EventID: "e3", Plate: "ABC123", CameraID: "cam-east", LocationID: "lot-a", TS: now, Make: "Toyota", Confidence: 0.89, Attrs: map[string]string{"bumper_sticker": "yes"}},
	}
}
