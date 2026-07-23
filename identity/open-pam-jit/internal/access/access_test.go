package access

import (
	"testing"
	"time"

	"github.com/Schildkrote/open-pam-jit/internal/audit"
	"github.com/Schildkrote/open-pam-jit/internal/vault"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	v, err := vault.New("pw", []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(v, audit.New(nil))
	m.AddTarget(Target{ID: "db", Name: "DB", Type: "database"})
	return m
}

func TestRequestApproveCredentialLifecycle(t *testing.T) {
	m := newTestManager(t)
	req, err := m.RequestAccess("alice", "db", "incident", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != "pending" {
		t.Fatalf("expected pending, got %s", req.Status)
	}

	cred, err := m.Approve(req.ID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := m.Validate(cred.ID); !ok {
		t.Fatalf("credential should be valid: %s", reason)
	}
	secret, err := m.GetSecret(cred.ID)
	if err != nil || secret == "" {
		t.Fatalf("expected a secret, got %q err=%v", secret, err)
	}

	if err := m.Revoke(cred.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Validate(cred.ID); ok {
		t.Fatal("revoked credential should be invalid")
	}
	if _, err := m.GetSecret(cred.ID); err == nil {
		t.Fatal("secret should be unavailable after revocation")
	}
}

func TestExpiry(t *testing.T) {
	m := newTestManager(t)
	m.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	req, _ := m.RequestAccess("alice", "db", "x", 60)
	cred, _ := m.Approve(req.ID, "bob")

	m.now = func() time.Time { return time.Unix(1000, 0).UTC().Add(61 * time.Second) }
	if ok, reason := m.Validate(cred.ID); ok || reason != "expired" {
		t.Fatalf("expected expired, got ok=%v reason=%s", ok, reason)
	}
}

func TestDeny(t *testing.T) {
	m := newTestManager(t)
	req, _ := m.RequestAccess("alice", "db", "x", 60)
	if err := m.Deny(req.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Approve(req.ID, "bob"); err == nil {
		t.Fatal("cannot approve a denied request")
	}
}

func TestBreakGlass(t *testing.T) {
	m := newTestManager(t)
	cred, err := m.BreakGlass("oncall", "db", "outage")
	if err != nil {
		t.Fatal(err)
	}
	if !cred.BreakGlass {
		t.Fatal("credential should be flagged break-glass")
	}
	if ok, _ := m.Validate(cred.ID); !ok {
		t.Fatal("break-glass credential should be valid")
	}
}

func TestUnknownTarget(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.RequestAccess("alice", "nope", "x", 60); err == nil {
		t.Fatal("expected error for unknown target")
	}
}
