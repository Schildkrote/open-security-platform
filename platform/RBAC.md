# RBAC, multi-tenancy & telemetry convention

Shared authorization and observability model for the platform (Phase 4), built on
`platform/auth` (JWT), `platform/rbac`, and `platform/telemetry`.

## RBAC

- A token carries **roles** (`claims.roles`) and/or direct **scopes**
  (`claims.scopes`). A role expands to a set of scopes (`platform/rbac.DefaultRoles`):
  - `admin` → `*` (everything)
  - `analyst` → read/write cases, findings, evidence; run actions
  - `operator` → read cases/findings; run actions
  - `viewer` → read cases/findings/evidence
- **Effective scopes** = union of direct scopes + role scopes (`rbac.Scopes`).
- **Permission check:** `rbac.Can(claims, roles, "cases:write")` (`*` grants all).
- Permission names follow `<resource>:<action>` (e.g. `findings:read`,
  `actions:run`). Components enforce decisions in their own middleware (Go:
  `platform/auth.Middleware` for authentication + an `rbac.Can` check for
  authorization).

## Multi-tenancy

- A token carries a **tenant** (`claims.tenant`). Components scope stored data by
  tenant (e.g. a `tenant` column / prefix) and filter reads by
  `rbac.Tenant(claims)`.
- Convention: every tenant-scoped table has a `tenant TEXT` column; queries
  always filter on it. Cross-tenant access requires `admin`.

## Telemetry

- Components emit counters/spans through the `telemetry.Meter` interface.
- Offline default: `telemetry.Noop` (discards). Tests: `telemetry.InMemory`.
- Production: `telemetry.NewOTLP(endpoint)` exports OTLP/HTTP to a collector
  (OpenTelemetry/Prometheus). Best-effort; never blocks the request path.

## Status

- `platform/auth` (JWT), `platform/rbac` (roles/scopes/tenant), and
  `platform/telemetry` (Noop/InMemory/OTLP) are implemented and tested.
- Enforcing RBAC + tenant scoping in each component's storage/API is incremental
  follow-up; the shared model means roles/permissions/tenant are consistent
  everywhere.
