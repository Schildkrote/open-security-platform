package registry

import "testing"

func TestRegisterAndAllow(t *testing.T) {
	r := New()
	r.Register(Tool{Name: "web-search", Kind: "mcp", Risk: RiskLow, Allowed: true})
	r.Register(Tool{Name: "shell-exec", Kind: "function", Risk: RiskCritical, Allowed: false})

	if !r.IsAllowed("web-search") {
		t.Error("web-search should be allowed")
	}
	if r.IsAllowed("shell-exec") {
		t.Error("shell-exec should not be allowed")
	}
	if r.IsAllowed("missing") {
		t.Error("unknown tool should not be allowed")
	}

	if !r.SetAllowed("shell-exec", true) {
		t.Error("SetAllowed on existing tool should succeed")
	}
	if !r.IsAllowed("shell-exec") {
		t.Error("shell-exec should be allowed after update")
	}
	if len(r.List()) != 2 {
		t.Errorf("expected 2 tools, got %d", len(r.List()))
	}
}
