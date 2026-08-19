// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package policy evaluates purpose × role × classification at decision time.
package policy

import (
	"fmt"
	"strings"
)

// Purpose constants.
const (
	PurposeInvestigation = "investigation"
	PurposeClientProtect = "client_protection"
	PurposePatrolAlert   = "patrol_alert"
	PurposePatternOfLife = "pattern_of_life"
	PurposeAdmin         = "admin"
	PurposeResearch      = "research"
)

// Role constants.
const (
	RoleAnalyst   = "analyst"
	RoleOfficer   = "officer"
	RoleAgent     = "agent" // AI agent
	RoleAdmin     = "admin"
	RoleClientApp = "client_app"
)

// Decision outcomes.
const (
	Allow           = "allow"
	Deny            = "deny"
	RequireWarrant  = "require_warrant"
	RequireCase     = "require_case"
	RequireApproval = "require_approval"
)

// Request is evaluated at every read/action.
type Request struct {
	Purpose        string
	Role           string
	Classification string // object classification
	ObjectType     string
	Action         string // read|write|action:<name>
	HasWarrant     bool
	HasCase        bool
	CaseID         string
	WarrantID      string
	NeedToKnow     bool // caller asserts NTK; real systems derive this
}

// Decision is the policy result.
type Decision struct {
	Outcome string
	Reason  string
	Allowed bool
}

// Evaluate applies default-deny with LE-aware ALPR rules.
func Evaluate(r Request) Decision {
	r.Purpose = strings.ToLower(strings.TrimSpace(r.Purpose))
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Classification = strings.ToLower(strings.TrimSpace(r.Classification))
	r.ObjectType = strings.TrimSpace(r.ObjectType)
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))

	if r.Purpose == "" || r.Role == "" {
		return Decision{Outcome: Deny, Reason: "purpose and role required"}
	}
	if r.Classification == "" {
		r.Classification = "internal"
	}
	if r.Action == "" {
		r.Action = "read"
	}

	// Secret always needs admin or warrant+case for LE roles.
	if r.Classification == "secret" && r.Role != RoleAdmin {
		if !(r.HasWarrant && r.HasCase && (r.Role == RoleOfficer || r.Role == RoleAnalyst)) {
			return Decision{Outcome: Deny, Reason: "secret requires admin or warrant+case LE context"}
		}
	}

	// Client protection path: client_app or analyst, no ALPR bulk.
	if r.Purpose == PurposeClientProtect {
		if r.Role != RoleClientApp && r.Role != RoleAnalyst && r.Role != RoleAdmin && r.Role != RoleAgent {
			return Decision{Outcome: Deny, Reason: "client_protection: role not permitted"}
		}
		if isALPRHistorical(r) {
			return Decision{Outcome: Deny, Reason: "client_protection cannot run ALPR pattern-of-life"}
		}
		return Decision{Outcome: Allow, Allowed: true, Reason: "client_protection allow"}
	}

	// ALPR / vehicle pattern-of-life: warrant or active case by default.
	if isALPRHistorical(r) || r.Purpose == PurposePatternOfLife {
		if r.Role != RoleOfficer && r.Role != RoleAnalyst && r.Role != RoleAdmin {
			return Decision{Outcome: Deny, Reason: "ALPR historical: LE role required"}
		}
		if r.HasWarrant {
			return Decision{Outcome: Allow, Allowed: true, Reason: "ALPR historical with warrant"}
		}
		if r.HasCase {
			return Decision{Outcome: RequireWarrant, Reason: "active case present but warrant recommended/required by pack"}
		}
		return Decision{Outcome: RequireWarrant, Reason: "ALPR historical / pattern-of-life requires warrant context"}
	}

	// Live hotlist patrol alert — plate read vs hotlist only (not historical dump).
	if r.Purpose == PurposePatrolAlert {
		if r.Role != RoleOfficer && r.Role != RoleAdmin && r.Role != RoleAgent {
			return Decision{Outcome: Deny, Reason: "patrol_alert: officer/admin/agent only"}
		}
		if r.ObjectType == "PlateRead" || r.Action == "action:issue_alert" || r.Action == "read" {
			return Decision{Outcome: Allow, Allowed: true, Reason: "live hotlist patrol"}
		}
	}

	// Investigation with case.
	if r.Purpose == PurposeInvestigation {
		if r.Role == RoleAdmin {
			return Decision{Outcome: Allow, Allowed: true, Reason: "admin investigation"}
		}
		if r.Role != RoleOfficer && r.Role != RoleAnalyst && r.Role != RoleAgent {
			return Decision{Outcome: Deny, Reason: "investigation: LE/analyst role required"}
		}
		if !r.HasCase && r.Classification != "public" {
			return Decision{Outcome: RequireCase, Reason: "investigation on non-public data requires case id"}
		}
		return Decision{Outcome: Allow, Allowed: true, Reason: "investigation with case"}
	}

	if r.Purpose == PurposeAdmin && r.Role == RoleAdmin {
		return Decision{Outcome: Allow, Allowed: true, Reason: "admin"}
	}

	if r.Purpose == PurposeResearch {
		if r.Classification == "public" {
			return Decision{Outcome: Allow, Allowed: true, Reason: "public research"}
		}
		return Decision{Outcome: Deny, Reason: "research limited to public classification"}
	}

	// Sensitive actions always need approval unless admin.
	if strings.HasPrefix(r.Action, "action:") && r.Role != RoleAdmin {
		switch r.Action {
		case "action:issue_alert", "action:open_case":
			// allowed if purpose already passed
		case "action:task_sensor", "action:request_warrant_package":
			if !r.HasCase {
				return Decision{Outcome: RequireCase, Reason: "sensor task / warrant package needs case"}
			}
		default:
			if r.Role == RoleAgent {
				return Decision{Outcome: RequireApproval, Reason: "agent actions need human approval by default"}
			}
		}
	}

	return Decision{Outcome: Deny, Reason: fmt.Sprintf("no rule matched purpose=%s role=%s", r.Purpose, r.Role)}
}

func isALPRHistorical(r Request) bool {
	if r.Purpose == PurposePatternOfLife {
		return true
	}
	if r.ObjectType == "PlateRead" && (r.Action == "read" || r.Action == "query_historical") {
		// live single-read for patrol is handled above via purpose
		if r.Purpose == PurposePatrolAlert {
			return false
		}
		return r.Purpose != PurposePatrolAlert
	}
	if r.Action == "query_historical" {
		return true
	}
	return false
}

// MustAllow panics-free helper.
func MustAllow(r Request) error {
	d := Evaluate(r)
	if d.Allowed {
		return nil
	}
	return fmt.Errorf("policy %s: %s", d.Outcome, d.Reason)
}
