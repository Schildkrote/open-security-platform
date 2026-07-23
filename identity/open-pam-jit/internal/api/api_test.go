package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Schildkrote/open-pam-jit/internal/access"
	"github.com/Schildkrote/open-pam-jit/internal/audit"
	"github.com/Schildkrote/open-pam-jit/internal/vault"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	v, err := vault.New("pw", []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.New(nil)
	mgr := access.NewManager(v, logger)
	mgr.AddTarget(access.Target{ID: "db", Name: "DB", Type: "database"})
	return (&Server{Mgr: mgr, Audit: logger}).Routes()
}

func do(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestEndToEndAccessFlow(t *testing.T) {
	h := newTestServer(t)

	// Request access.
	rr := do(t, h, "POST", "/requests", map[string]any{
		"requester": "alice", "target_id": "db", "justification": "incident", "duration_sec": 3600,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("request: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var req access.Request
	_ = json.Unmarshal(rr.Body.Bytes(), &req)

	// Approve -> credential.
	rr = do(t, h, "POST", "/requests/"+req.ID+"/approve", map[string]any{"approver": "bob"})
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var cred access.Credential
	_ = json.Unmarshal(rr.Body.Bytes(), &cred)

	// Validate + fetch secret.
	rr = do(t, h, "POST", "/credentials/"+cred.ID+"/validate", nil)
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"valid":true`)) {
		t.Fatalf("expected valid credential: %s", rr.Body.String())
	}
	rr = do(t, h, "POST", "/credentials/"+cred.ID+"/secret", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("secret: expected 200, got %d", rr.Code)
	}

	// Revoke -> secret no longer available.
	do(t, h, "POST", "/credentials/"+cred.ID+"/revoke", map[string]any{"actor": "bob"})
	rr = do(t, h, "POST", "/credentials/"+cred.ID+"/secret", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after revoke, got %d", rr.Code)
	}
}

func TestBreakGlassAndSession(t *testing.T) {
	h := newTestServer(t)

	rr := do(t, h, "POST", "/break-glass", map[string]any{"requester": "oncall", "target_id": "db", "reason": "outage"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("break-glass: expected 201, got %d", rr.Code)
	}

	rr = do(t, h, "POST", "/sessions", map[string]any{"user": "alice", "target": "db", "commands": []string{"SELECT 1"}})
	if rr.Code != http.StatusCreated {
		t.Fatalf("session: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"verified":true`)) {
		t.Fatalf("session transcript should verify: %s", rr.Body.String())
	}

	rr = do(t, h, "GET", "/audit/verify", nil)
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"valid":true`)) {
		t.Fatalf("audit chain should verify: %s", rr.Body.String())
	}
}
