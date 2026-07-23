package policy

import "testing"

func TestEvaluateDenyModel(t *testing.T) {
	e := &Engine{Default: Allow, Rules: []Rule{
		{Name: "block-legacy", ModelPattern: "^gpt-3", Action: Deny, Reason: "deprecated"},
	}}
	if err := e.Compile(); err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(Request{Model: "gpt-3.5-turbo"})
	if d.Action != Deny || d.Rule != "block-legacy" {
		t.Fatalf("expected deny by block-legacy, got %+v", d)
	}
	if got := e.Evaluate(Request{Model: "gpt-4o"}); got.Action != Allow {
		t.Fatalf("expected allow, got %+v", got)
	}
}

func TestEvaluateContentRedact(t *testing.T) {
	e := &Engine{Default: Allow, Rules: []Rule{
		{Name: "redact-ssn", ContentRe: `\d{3}-\d{2}-\d{4}`, Action: Redact},
	}}
	if err := e.Compile(); err != nil {
		t.Fatal(err)
	}
	d := e.Evaluate(Request{Content: "my ssn is 123-45-6789"})
	if d.Action != Redact {
		t.Fatalf("expected redact, got %+v", d)
	}
}

func TestEvaluateAPIKeyScope(t *testing.T) {
	e := &Engine{Default: Deny, Rules: []Rule{
		{Name: "team-a", APIKeys: []string{"key-a"}, Action: Allow},
	}}
	_ = e.Compile()
	if d := e.Evaluate(Request{APIKey: "key-a"}); d.Action != Allow {
		t.Fatalf("expected allow for key-a, got %+v", d)
	}
	if d := e.Evaluate(Request{APIKey: "key-b"}); d.Action != Deny {
		t.Fatalf("expected default deny for key-b, got %+v", d)
	}
}
