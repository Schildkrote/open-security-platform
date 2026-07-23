// Package auth provides shared OIDC-style JWT authentication and RBAC for the
// Go components of open-security-platform (Phase-1 backbone).
//
// It verifies HS256-signed JWTs (the subset of OIDC needed for service-to-service
// trust) using stdlib only, so any component can accept a token minted by the
// platform's IdP (a real Keycloak in production, the bundled mock IdP offline).
// Tokens minted/verified here use the same claims shape across components, so a
// token issued for one component is accepted by another.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Claims is the platform JWT claims set.
type Claims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss,omitempty"`
	Audience string   `json:"aud,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	IssuedAt int64    `json:"iat,omitempty"`
	Expires  int64    `json:"exp,omitempty"`
}

// Errors returned by Verify.
var (
	ErrMalformed = errors.New("auth: malformed token")
	ErrSignature = errors.New("auth: invalid signature")
	ErrExpired   = errors.New("auth: token expired")
)

var b64 = base64.RawURLEncoding

// IssueToken mints an HS256 JWT for subject with the given scopes and TTL.
// Used by the mock IdP and tests; a real deployment uses Keycloak instead.
func IssueToken(subject, issuer string, scopes []string, ttl time.Duration, secret string) (string, error) {
	now := time.Now()
	return Sign(Claims{
		Subject:  subject,
		Issuer:   issuer,
		Scopes:   scopes,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
	}, secret)
}

// Sign encodes claims as an HS256 JWT.
func Sign(claims Claims, secret string) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := mac([]byte(signingInput), secret)
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// Verify checks the HS256 signature and expiry and returns the claims.
func Verify(token, secret string) (Claims, error) {
	var claims Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, ErrMalformed
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return claims, ErrMalformed
	}
	if !hmac.Equal(sig, mac([]byte(signingInput), secret)) {
		return claims, ErrSignature
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return claims, ErrMalformed
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, ErrMalformed
	}
	if claims.Expires != 0 && time.Now().Unix() > claims.Expires {
		return claims, ErrExpired
	}
	return claims, nil
}

// HasScope reports whether the claims carry the given scope. An empty required
// scope always matches (used to require only authentication, not a role).
func HasScope(claims Claims, scope string) bool {
	if scope == "" {
		return true
	}
	for _, s := range claims.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Middleware guards next with HS256 JWT authentication. A missing/invalid token
// yields 401; a valid token lacking requiredScope yields 403. A empty secret
// disables auth (passthrough) so components stay open by default offline.
func Middleware(secret, requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := bearer(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := Verify(token, secret)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !HasScope(claims, requiredScope) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func mac(data []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return h.Sum(nil)
}
