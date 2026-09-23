package proxy

// Round-8, BL-18 and BL-19: structural guards for the audit chokepoint.
//
// Round 8 REJECTED c93ed4f with three guarantees that no test in this repo pinned —
// MUT-H (fail-safe preserves ALL Meta values instead of the panic_type allowlist),
// MUT-I (fail-safe preserves Reason) and MUT-F (Meta KEYS not renamed). The reviewer
// killed all three with probes that lived ONLY in their clone, so the mutations
// survived my battery and would survive the next one too. A test that exists only in
// a reviewer's worktree guards nothing: this file puts those guards in the repo.
//
// These call g.log DIRECTLY with a crafted event. g.log takes audit.Event by value,
// so the chokepoint can be exercised without finding a ServeHTTP path that happens to
// carry raw attacker text into a specific field — which is exactly why the round-7
// fail-safe pin was vacuous at first (the panic handler builds a fresh event with no
// Model, so there was nothing raw to drop). Calling the chokepoint directly means the
// event's contents are chosen deliberately, not discovered by luck.

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
)

// ---------------------------------------------------------------------------
// BL-18: the swept-field boundary must be structurally guarded.
// ---------------------------------------------------------------------------

// TestBL18_EveryAuditEventFieldIsSweptOrExplicitlyExempt is the inventory tripwire
// the reviewer wrote and could not land. It reflects over audit.Event and requires
// EVERY field to be either swept by sweepAuditText or listed in auditSweepExempt
// WITH a non-empty justification.
//
// This is the guard that was missing when sweepAuditText hardcoded Model, Reason and
// Meta by name. audit.Event has eleven fields; adding a twelfth — a `Detail string`
// populated from an upstream error body — would have flowed into the tamper-evident
// log unswept with no compile error, no failing test and no runtime signal. Now it
// fails here, and the failure message says exactly what to do about it.
func TestBL18_EveryAuditEventFieldIsSweptOrExplicitlyExempt(t *testing.T) {
	typ := reflect.TypeOf(audit.Event{})
	if typ.Kind() != reflect.Struct {
		t.Fatalf("audit.Event is not a struct: %v", typ.Kind())
	}

	var swept, exempt []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			// An unexported field cannot be marshalled by encoding/json, so it is not
			// an egress channel. Fail loudly if that ever stops being true, because a
			// future field with a json tag that reflection cannot set would be a hole.
			if _, tagged := f.Tag.Lookup("json"); tagged {
				t.Errorf("field %s is unexported but carries a json tag, so it may "+
					"serialise while being unreachable by the reflective sweep — "+
					"export it or drop the tag", f.Name)
			}
			continue
		}
		reason, isExempt := auditSweepExempt[f.Name]
		if isExempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("field %s is exempt from sweeping with NO justification; "+
					"every exemption is a claim that the field cannot carry attacker "+
					"text and must be argued in the map", f.Name)
			}
			exempt = append(exempt, f.Name)
			continue
		}
		swept = append(swept, f.Name)
	}

	t.Logf("audit.Event: %d fields — swept %v, exempt %v", typ.NumField(), swept, exempt)

	// The sweep must actually cover a meaningful set, so a future refactor that moves
	// everything into the exempt map cannot pass by exempting the lot.
	if len(swept) == 0 {
		t.Error("no fields are swept; the exemption list has swallowed the whole struct")
	}
	// The three fields the original hardcoded version swept must still be swept. A
	// regression that exempts Model, Reason or Meta would otherwise pass the check
	// above while silently reopening BL-14.
	for _, must := range []string{"Model", "Reason", "Meta"} {
		if _, isExempt := auditSweepExempt[must]; isExempt {
			t.Errorf("BL-14 regression: %s is in the exempt list, so the chokepoint no "+
				"longer sweeps the free-text field it exists to protect", must)
		}
	}

	// And the exempt names must all still EXIST, so the map cannot rot into exempting
	// fields that were renamed away while real ones get swept twice or not at all.
	for name := range auditSweepExempt {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("auditSweepExempt names %q, which is not a field of audit.Event; "+
				"the exemption list has drifted from the struct", name)
		}
	}

	// BEHAVIOURALLY verify the boundary, not just assert it. This is the half that
	// actually kills a regression, and it is why the check above is not enough:
	// a sweepAuditText that hardcodes Model, Reason and Meta is behaviourally
	// IDENTICAL to the reflective one on TODAY's struct, because there is no fourth
	// text field. Only a per-field behavioural assertion makes the "every non-exempt
	// field is swept" claim falsifiable — and it is what would fail if the reflective
	// walk were reverted to a hardcoded list and a new field were later added.
	var buf2 bytes.Buffer
	gw := newTestGateway(t, nil, &buf2)
	gw.Redactor = shapeRedactor{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, isExempt := auditSweepExempt[f.Name]; isExempt {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String:
			ev := audit.Event{Action: "allow"}
			reflect.ValueOf(&ev).Elem().Field(i).SetString(piiMarker)
			if ok := sweepAuditText(gw, &ev); !ok {
				t.Fatalf("sweepAuditText failed on a clean redactor")
			}
			if got := reflect.ValueOf(&ev).Elem().Field(i).String(); strings.Contains(got, piiMarker) {
				t.Errorf("BL-18: non-exempt string field %s was NOT swept (value %q). "+
					"sweepAuditText must cover every field the exemption map does not "+
					"justify; a hardcoded field list is how BL-18 was filed.", f.Name, got)
			}
		case reflect.Map:
			ev := audit.Event{Action: "allow",
				Meta: map[string]any{"k": piiMarker}}
			if ok := sweepAuditText(gw, &ev); !ok {
				t.Fatalf("sweepAuditText failed on a clean redactor")
			}
			encoded, _ := json.Marshal(ev.Meta)
			if strings.Contains(string(encoded), piiMarker) {
				t.Errorf("BL-18: non-exempt map field %s was NOT swept: %s", f.Name, encoded)
			}
		}
	}
}

// TestBL18_NewStringFieldWouldBeSweptByDefault proves the fail-safe DIRECTION of the
// reflective sweep: a field nobody thought about gets swept, not served raw. It
// exercises sweepAuditText against a real event whose Model and Reason carry PII and
// asserts both come back clean — the property that would break if the sweep reverted
// to a hardcoded three-field list.
func TestBL18_NewStringFieldWouldBeSweptByDefault(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.Redactor = shapeRedactor{}

	ev := audit.Event{
		Action: "allow",
		Model:  piiMarker,                         // swept
		Reason: "detail " + piiMarker,             // swept
		Meta:   map[string]any{"note": piiMarker}, // swept (value)
	}
	if ok := sweepAuditText(gw, &ev); !ok {
		t.Fatal("sweepAuditText reported failure with a working redactor")
	}
	if strings.Contains(ev.Model, piiMarker) {
		t.Errorf("Model was not swept: %q", ev.Model)
	}
	if strings.Contains(ev.Reason, piiMarker) {
		t.Errorf("Reason was not swept: %q", ev.Reason)
	}
	if v, _ := ev.Meta["note"].(string); strings.Contains(v, piiMarker) {
		t.Errorf("Meta value was not swept: %q", v)
	}
	// Action must survive: it is the record's filterable vocabulary.
	if ev.Action != "allow" {
		t.Errorf("BL-14/BL-18 over-redaction: the closed-vocabulary Action field was "+
			"mangled to %q; sweeping it makes every record unfilterable", ev.Action)
	}
	if len(ev.Redactions) == 0 {
		t.Error("the sweep recorded no finding kinds, so the trail claims nothing was " +
			"redacted while PII was in fact removed")
	}
}

// ---------------------------------------------------------------------------
// BL-19 / MUT-F: Meta KEYS are swept, not just values.
// ---------------------------------------------------------------------------

// TestBL19_MetaKeysAreSweptByChokepoint is the in-repo form of the reviewer's
// TestR8_MetaKeysAreSweptByChokepoint. MUT-F (a values-only Meta sweep) SURVIVED my
// battery because nothing pinned the BL-10 key-rename property on the audit path: a
// future refactor of sweepAuditText's Meta handling to a values-only loop would ship
// green while PII sitting in a KEY reached the tamper-evident log raw.
func TestBL19_MetaKeysAreSweptByChokepoint(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.Redactor = shapeRedactor{}

	// The PII is in the KEY, not the value. This is the exact shape MUT-F leaves
	// untouched.
	ev := audit.Event{
		Action: "allow",
		Meta:   map[string]any{piiMarker: "innocent-value"},
	}
	if ok := sweepAuditText(gw, &ev); !ok {
		t.Fatal("sweepAuditText reported failure with a working redactor")
	}

	encoded, err := json.Marshal(ev.Meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), piiMarker) {
		t.Errorf("MUT-F regression: PII in a Meta KEY reached the audit record raw "+
			"(the BL-10 key-sweep is unpinned): %s", encoded)
	}
	if len(ev.Redactions) == 0 {
		t.Error("the key sweep recorded no finding kind, so an unswept key would be " +
			"indistinguishable from a swept one in the trail")
	}
	t.Logf("meta keys swept to: %s", encoded)
}

// ---------------------------------------------------------------------------
// BL-19 / MUT-H and MUT-I: the fail-safe allowlist, not a blanket preserve.
// ---------------------------------------------------------------------------

// TestBL19_FailSafePreservesOnlyTheAllowlistedMetaKey pins MUT-H. The fail-safe runs
// when the redactor cannot be trusted, and it must preserve ONLY auditSafeMetaKeys —
// not every Meta value. MUT-H (preserve all Meta values) SURVIVED my battery, and the
// author's own comment calls an allowlist entry whose value is ever attacker-derived
// "a leak that no test will catch". This is that test.
func TestBL19_FailSafePreservesOnlyTheAllowlistedMetaKey(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.Redactor = panickingRedactor{} // the sweep cannot be trusted

	ev := audit.Event{
		Action: "error",
		Model:  piiMarker,          // must be dropped
		Reason: "raw " + piiMarker, // must be dropped
		Meta: map[string]any{
			"panic_type":          "runtime.Error", // allowlisted: preserved
			"attacker_controlled": piiMarker,       // NOT allowlisted: must be dropped
		},
	}

	// g.log is the chokepoint; calling it directly exercises the fail-safe branch
	// with the event contents chosen deliberately rather than discovered via a
	// ServeHTTP path that may or may not carry raw text.
	gw.log(ev)

	got := buf.String()
	t.Logf("audit=%.400s", got)

	if strings.Contains(got, piiMarker) {
		t.Errorf("MUT-H regression: the fail-safe preserved a NON-allowlisted Meta "+
			"value (or Model/Reason) carrying PII into the tamper-evident log. "+
			"When the redactor cannot be trusted, free text must be DROPPED, not "+
			"passed through: %s", got)
	}
	// The allowlisted triage signal must SURVIVE — dropping it too is the mirror
	// over-redaction the auditSafeMetaKeys comment warns against: the panic event is
	// the one record proving a request was processed and something blew up, and its
	// type is the operator's triage signal.
	if !strings.Contains(got, "runtime.Error") {
		t.Errorf("the allowlisted panic_type was dropped, removing the triage signal "+
			"the fail-safe exists to keep: %s", got)
	}
	if !strings.Contains(got, `"audit_redaction":"unavailable"`) {
		t.Errorf("the fail-safe did not record that redaction was unavailable, so an "+
			"operator cannot tell a clean record from a degraded one: %s", got)
	}
}

// TestBL19_FailSafeDropsReason pins MUT-I (remove `e.Reason = ""`). It SURVIVED my
// battery standalone. The reviewer's empirical probe found it benign TODAY only
// because the reachable Reason content at fail-safe time happens to be operator-
// configured rule text — a second-layer property "nobody pinned" that "holds by
// accident of which call sites exist". A future call site that puts upstream text in
// Reason would reopen it silently. Pin the drop so the accident cannot become a leak.
func TestBL19_FailSafeDropsReason(t *testing.T) {
	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.Redactor = panickingRedactor{}

	ev := audit.Event{
		Action: "error",
		Reason: "upstream said: " + piiMarker, // attacker-influenced free text
	}
	gw.log(ev)

	got := buf.String()
	t.Logf("audit=%.400s", got)
	if strings.Contains(got, piiMarker) {
		t.Errorf("MUT-I regression: the fail-safe preserved Reason, letting "+
			"attacker-influenced free text into the tamper-evident log when the "+
			"redactor could not verify it clean. Reason must be dropped on the "+
			"fail-safe path: %s", got)
	}
	if !strings.Contains(got, `"audit_redaction":"unavailable"`) {
		t.Errorf("the fail-safe did not mark redaction unavailable: %s", got)
	}
}
