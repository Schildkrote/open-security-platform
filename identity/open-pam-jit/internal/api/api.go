// Package api exposes the PAM/JIT broker over HTTP.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/Schildkrote/open-pam-jit/internal/access"
	"github.com/Schildkrote/open-pam-jit/internal/audit"
	"github.com/Schildkrote/open-pam-jit/internal/session"
	"github.com/Schildkrote/platform/events"
)

type Server struct {
	Mgr    *access.Manager
	Audit  *audit.Logger
	Events *events.Emitter
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /targets", func(w http.ResponseWriter, r *http.Request) {
		var t access.Target
		if err := decode(r, &t); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.Mgr.AddTarget(t)
		writeJSON(w, http.StatusCreated, t)
	})

	mux.HandleFunc("POST /requests", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Requester     string `json:"requester"`
			TargetID      string `json:"target_id"`
			Justification string `json:"justification"`
			DurationSec   int    `json:"duration_sec"`
		}
		if err := decode(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req, err := s.Mgr.RequestAccess(body.Requester, body.TargetID, body.Justification, body.DurationSec)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, req)
	})

	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Mgr.ListRequests())
	})

	mux.HandleFunc("POST /requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Approver string `json:"approver"`
		}
		_ = decode(r, &body)
		cred, err := s.Mgr.Approve(r.PathValue("id"), body.Approver)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.emitAccess(cred, body.Approver, r.PathValue("id"))
		writeJSON(w, http.StatusOK, cred)
	})

	mux.HandleFunc("POST /requests/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Approver string `json:"approver"`
		}
		_ = decode(r, &body)
		if err := s.Mgr.Deny(r.PathValue("id"), body.Approver); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
	})

	mux.HandleFunc("POST /break-glass", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Requester string `json:"requester"`
			TargetID  string `json:"target_id"`
			Reason    string `json:"reason"`
		}
		if err := decode(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cred, err := s.Mgr.BreakGlass(body.Requester, body.TargetID, body.Reason)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.emitAccess(cred, body.Requester, "")
		writeJSON(w, http.StatusCreated, cred)
	})

	mux.HandleFunc("POST /credentials/{id}/validate", func(w http.ResponseWriter, r *http.Request) {
		ok, reason := s.Mgr.Validate(r.PathValue("id"))
		writeJSON(w, http.StatusOK, map[string]any{"valid": ok, "reason": reason})
	})

	mux.HandleFunc("POST /credentials/{id}/secret", func(w http.ResponseWriter, r *http.Request) {
		secret, err := s.Mgr.GetSecret(r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
	})

	mux.HandleFunc("POST /credentials/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Actor string `json:"actor"`
		}
		_ = decode(r, &body)
		if err := s.Mgr.Revoke(r.PathValue("id"), body.Actor); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	})

	mux.HandleFunc("GET /credentials", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Mgr.ListCredentials())
	})

	// Simulated privileged session recording (offline stand-in for SSH/DB).
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			User     string   `json:"user"`
			Target   string   `json:"target"`
			Commands []string `json:"commands"`
		}
		if err := decode(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		sess := session.Start("sess-"+body.User, body.User, body.Target)
		for _, cmd := range body.Commands {
			sess.Record("command", cmd)
			sess.Record("output", "(simulated) executed: "+cmd)
		}
		sess.End()
		s.Audit.Log(body.User, "session_recorded", body.Target, "commands="+itoa(len(body.Commands)))
		writeJSON(w, http.StatusCreated, map[string]any{
			"transcript": sess.Transcript(),
			"verified":   sess.Verify(),
		})
	})

	mux.HandleFunc("GET /audit/verify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"valid": s.Audit.Verify()})
	})

	return mux
}

// emitAccess publishes an access.granted integration event (opt-in, best-effort).
func (s *Server) emitAccess(cred *access.Credential, actor, requestID string) {
	if s.Events == nil {
		return
	}
	refs := map[string]any{"target_id": cred.TargetID}
	if requestID != "" {
		refs["request_id"] = requestID
	}
	_, _ = s.Events.Emit("access.granted", "approve", cred.ID, refs, map[string]any{
		"actor":       actor,
		"break_glass": cred.BreakGlass,
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
