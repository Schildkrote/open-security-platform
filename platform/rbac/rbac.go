// Package rbac provides shared role-based access control and multi-tenancy for
// the Go components (Phase 4). It builds on platform/auth claims: a token's
// roles expand to scopes, permissions are checked against scopes, and a tenant
// claim isolates data per-tenant. Components enforce decisions with their own
// middleware; this package supplies the shared model so roles/permissions mean
// the same thing everywhere.
package rbac

import "github.com/Schildkrote/platform/auth"

// Role is a named set of scopes (permissions).
type Role struct {
	Name   string
	Scopes []string
}

// DefaultRoles is the platform's built-in role hierarchy. "*" grants everything.
var DefaultRoles = []Role{
	{Name: "admin", Scopes: []string{"*"}},
	{Name: "analyst", Scopes: []string{
		"cases:read", "cases:write", "findings:read", "findings:write",
		"evidence:read", "evidence:write", "actions:run",
	}},
	{Name: "operator", Scopes: []string{"cases:read", "findings:read", "actions:run"}},
	{Name: "viewer", Scopes: []string{"cases:read", "findings:read", "evidence:read"}},
}

func roleIndex(roles []Role) map[string][]string {
	idx := make(map[string][]string, len(roles))
	for _, r := range roles {
		idx[r.Name] = r.Scopes
	}
	return idx
}

// Scopes returns the effective permission set for the claims: the union of the
// token's direct scopes and the scopes of its roles.
func Scopes(claims auth.Claims, roles []Role) map[string]bool {
	idx := roleIndex(roles)
	out := map[string]bool{}
	for _, s := range claims.Scopes {
		out[s] = true
	}
	for _, r := range claims.Roles {
		for _, s := range idx[r] {
			out[s] = true
		}
	}
	return out
}

// Can reports whether the claims grant a permission. The "*" scope grants all.
func Can(claims auth.Claims, roles []Role, permission string) bool {
	scopes := Scopes(claims, roles)
	return scopes["*"] || scopes[permission]
}

// Tenant returns the claims' tenant (for multi-tenant data isolation).
func Tenant(claims auth.Claims) string {
	return claims.Tenant
}
