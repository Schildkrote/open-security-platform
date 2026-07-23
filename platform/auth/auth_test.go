package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const secret = "test-secret"

func TestSignVerifyRoundTrip(t *testing.T) {
	token, err := IssueToken("alice", "osp-mock-idp", []string{"gateway:admin", "read"}, time.Minute, secret)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := Verify(token, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "alice" || claims.Issuer != "osp-mock-idp" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if !HasScope(claims, "gateway:admin") || !HasScope(claims, "read") {
		t.Errorf("expected scopes present: %+v", claims.Scopes)
	}
	if HasScope(claims, "missing") {
		t.Error("HasScope matched a scope the token does not have")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	token, _ := IssueToken("alice", "idp", nil, time.Minute, secret)
	if _, err := Verify(token, "other-secret"); err != ErrSignature {
		t.Errorf("expected ErrSignature, got %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	token, _ := IssueToken("alice", "idp", nil, time.Minute, secret)
	parts := split3(token)
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]
	if _, err := Verify(tampered, secret); err == nil {
		t.Error("tampered token verified")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	if _, err := Verify("not.a.valid.token.at.all", secret); err == nil {
		t.Error("malformed token verified")
	}
	if _, err := Verify("onlyonepart", secret); err != ErrMalformed {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	token, _ := IssueToken("alice", "idp", nil, -time.Minute, secret)
	if _, err := Verify(token, secret); err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("no token -> 401", func(t *testing.T) {
		rr := serve(AuthedHandler(secret, "admin", ok), "GET", "/x", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("valid token, missing scope -> 403", func(t *testing.T) {
		token, _ := IssueToken("alice", "idp", []string{"read"}, time.Minute, secret)
		rr := serve(AuthedHandler(secret, "admin", ok), "GET", "/x", token)
		if rr.Code != http.StatusForbidden {
			t.Errorf("got %d, want 403", rr.Code)
		}
	})

	t.Run("valid token with scope -> 200", func(t *testing.T) {
		token, _ := IssueToken("alice", "idp", []string{"admin"}, time.Minute, secret)
		rr := serve(AuthedHandler(secret, "admin", ok), "GET", "/x", token)
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("empty secret -> passthrough", func(t *testing.T) {
		rr := serve(AuthedHandler("", "admin", ok), "GET", "/x", "")
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200 (auth disabled)", rr.Code)
		}
	})
}

// AuthedHandler wraps Middleware for tests.
func AuthedHandler(secret, scope string, next http.Handler) http.Handler {
	return Middleware(secret, scope, next)
}

func serve(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func split3(token string) [3]string {
	var out [3]string
	i, j := 0, 0
	for n := 0; n < len(token); n++ {
		if token[n] == '.' {
			out[i] = token[j:n]
			i++
			j = n + 1
		}
	}
	out[i] = token[j:]
	return out
}
