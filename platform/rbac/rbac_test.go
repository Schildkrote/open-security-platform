package rbac

import (
	"testing"

	"github.com/Schildkrote/platform/auth"
)

func TestAdminCanEverything(t *testing.T) {
	claims := auth.Claims{Subject: "root", Roles: []string{"admin"}}
	for _, perm := range []string{"cases:write", "findings:read", "anything:at-all"} {
		if !Can(claims, DefaultRoles, perm) {
			t.Errorf("admin should be able to %q", perm)
		}
	}
}

func TestViewerReadOnly(t *testing.T) {
	claims := auth.Claims{Subject: "v", Roles: []string{"viewer"}}
	if !Can(claims, DefaultRoles, "cases:read") {
		t.Error("viewer should read cases")
	}
	if Can(claims, DefaultRoles, "cases:write") {
		t.Error("viewer must not write cases")
	}
}

func TestDirectScopeGrants(t *testing.T) {
	claims := auth.Claims{Subject: "s", Scopes: []string{"actions:run"}}
	if !Can(claims, DefaultRoles, "actions:run") {
		t.Error("direct scope should grant")
	}
	if Can(claims, DefaultRoles, "cases:write") {
		t.Error("ungranted permission should deny")
	}
}

func TestRoleUnionWithScopes(t *testing.T) {
	claims := auth.Claims{Subject: "a", Roles: []string{"viewer"}, Scopes: []string{"actions:run"}}
	scopes := Scopes(claims, DefaultRoles)
	if !scopes["cases:read"] || !scopes["actions:run"] {
		t.Errorf("expected union of role + direct scopes, got %v", scopes)
	}
}

func TestTenant(t *testing.T) {
	if got := Tenant(auth.Claims{Tenant: "acme"}); got != "acme" {
		t.Errorf("Tenant = %q, want acme", got)
	}
}
