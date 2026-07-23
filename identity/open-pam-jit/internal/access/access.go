// Package access implements JIT privileged-access requests, approvals,
// temporary credentials, and break-glass.
package access

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Schildkrote/open-pam-jit/internal/audit"
)

// SecretStore is the swappable secrets backend (Phase 3). The local encrypted
// vault (internal/vault) and the OpenBao connector (internal/bao) both satisfy
// it, so credentials can live in OpenBao without changing the access logic.
type SecretStore interface {
	Put(name, secret string) error
	Get(name string) (string, error)
	Delete(name string)
}

type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // "ssh" | "database" | "cloud" | "k8s"
}

type Request struct {
	ID            string    `json:"id"`
	Requester     string    `json:"requester"`
	TargetID      string    `json:"target_id"`
	Justification string    `json:"justification"`
	DurationSec   int       `json:"duration_sec"`
	Status        string    `json:"status"` // pending | approved | denied
	DecidedBy     string    `json:"decided_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type Credential struct {
	ID         string    `json:"id"`
	RequestID  string    `json:"request_id,omitempty"`
	TargetID   string    `json:"target_id"`
	SecretName string    `json:"-"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
	BreakGlass bool      `json:"break_glass"`
}

type Manager struct {
	mu       sync.Mutex
	vault    SecretStore
	audit    *audit.Logger
	targets  map[string]Target
	requests map[string]*Request
	creds    map[string]*Credential
	now      func() time.Time
}

func NewManager(v SecretStore, a *audit.Logger) *Manager {
	return &Manager{
		vault:    v,
		audit:    a,
		targets:  map[string]Target{},
		requests: map[string]*Request{},
		creds:    map[string]*Credential{},
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (m *Manager) AddTarget(t Target) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targets[t.ID] = t
}

func (m *Manager) RequestAccess(requester, targetID, justification string, durationSec int) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[targetID]; !ok {
		return nil, errors.New("unknown target")
	}
	req := &Request{
		ID:            newID(),
		Requester:     requester,
		TargetID:      targetID,
		Justification: justification,
		DurationSec:   durationSec,
		Status:        "pending",
		CreatedAt:     m.now(),
	}
	m.requests[req.ID] = req
	m.audit.Log(requester, "access_requested", targetID, justification)
	return req, nil
}

// Approve grants the request and mints a temporary credential.
func (m *Manager) Approve(requestID, approver string) (*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[requestID]
	if !ok {
		return nil, errors.New("unknown request")
	}
	if req.Status != "pending" {
		return nil, errors.New("request already decided")
	}
	req.Status = "approved"
	req.DecidedBy = approver
	cred, err := m.mint(req.Requester, req.TargetID, req.DurationSec, requestID, false)
	if err != nil {
		return nil, err
	}
	m.audit.Log(approver, "access_approved", req.TargetID, "request="+requestID)
	return cred, nil
}

func (m *Manager) Deny(requestID, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[requestID]
	if !ok {
		return errors.New("unknown request")
	}
	req.Status = "denied"
	req.DecidedBy = approver
	m.audit.Log(approver, "access_denied", req.TargetID, "request="+requestID)
	return nil
}

// BreakGlass mints immediate short-lived access and logs it loudly.
func (m *Manager) BreakGlass(requester, targetID, reason string) (*Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[targetID]; !ok {
		return nil, errors.New("unknown target")
	}
	cred, err := m.mint(requester, targetID, 900, "", true) // 15 min
	if err != nil {
		return nil, err
	}
	m.audit.Log(requester, "BREAK_GLASS", targetID, reason)
	return cred, nil
}

// mint creates a credential and stores its secret in the vault. Caller holds lock.
func (m *Manager) mint(requester, targetID string, durationSec int, requestID string, breakGlass bool) (*Credential, error) {
	secret, err := randomSecret()
	if err != nil {
		return nil, err
	}
	cred := &Credential{
		ID:         newID(),
		RequestID:  requestID,
		TargetID:   targetID,
		SecretName: "cred-" + newID(),
		ExpiresAt:  m.now().Add(time.Duration(durationSec) * time.Second),
		BreakGlass: breakGlass,
	}
	if err := m.vault.Put(cred.SecretName, secret); err != nil {
		return nil, err
	}
	m.creds[cred.ID] = cred
	m.audit.Log(requester, "credential_minted", targetID, "ttl="+fmt.Sprint(durationSec)+"s")
	return cred, nil
}

// Validate reports whether a credential is currently usable.
func (m *Manager) Validate(credID string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok {
		return false, "unknown credential"
	}
	if c.Revoked {
		return false, "revoked"
	}
	if m.now().After(c.ExpiresAt) {
		return false, "expired"
	}
	return true, "valid"
}

// GetSecret returns the decrypted secret only if the credential is valid.
func (m *Manager) GetSecret(credID string) (string, error) {
	if ok, reason := m.Validate(credID); !ok {
		return "", errors.New(reason)
	}
	m.mu.Lock()
	c := m.creds[credID]
	m.mu.Unlock()
	return m.vault.Get(c.SecretName)
}

func (m *Manager) Revoke(credID, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok {
		return errors.New("unknown credential")
	}
	c.Revoked = true
	m.vault.Delete(c.SecretName)
	m.audit.Log(actor, "credential_revoked", c.TargetID, "cred="+credID)
	return nil
}

func (m *Manager) ListRequests() []*Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Request, 0, len(m.requests))
	for _, r := range m.requests {
		out = append(out, r)
	}
	return out
}

func (m *Manager) ListCredentials() []*Credential {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Credential, 0, len(m.creds))
	for _, c := range m.creds {
		out = append(out, c)
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
