package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The chokepoint invariant's blind spot, found while writing it.
//
// The sweep is total for JSON: it inspects every string in a decoded document,
// so no container or key name can hide PII. But it only runs when the upstream
// body DECODES AS JSON. proxy.go has a separate non-JSON path that passes error
// bodies through unredacted, on the reasoning that an upstream 502 HTML page is
// diagnostic rather than model output.
//
// That reasoning holds for a genuine proxy error page. It does not hold for a
// compromised or misconfigured upstream that returns MODEL OUTPUT under a non-2xx
// status with a non-JSON content type - which is exactly the reviewer's round-3
// question 3 (can an attacker get model output served under a non-2xx label?),
// reached by content type instead of by status.
// ---------------------------------------------------------------------------

func TestNonJSONErrorBodyIsNotAChannelForUnredactedModelOutput(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{
			"500 text/plain carrying model output",
			http.StatusInternalServerError, "text/plain",
			"upstream failed. last assistant message: " + piiMarker + "\n",
		},
		{
			"429 text/html carrying model output",
			http.StatusTooManyRequests, "text/html; charset=utf-8",
			"<html><body>rate limited. partial output: " + piiMarker + "</body></html>",
		},
		{
			"502 with no content-type at all",
			http.StatusBadGateway, "",
			"bad gateway, leaked: " + piiMarker,
		},
		{
			"500 application/xml carrying model output",
			http.StatusInternalServerError, "application/xml",
			"<error><detail>" + piiMarker + "</detail></error>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(up.Close)

			var buf bytes.Buffer
			gw := newTestGateway(t, nil, &buf)
			gw.UpstreamURL = up.URL
			gw.Redactor = shapeRedactor{}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("X-API-Key", longSecretKey)
			gw.ServeHTTP(rr, req)

			client := rr.Body.String()
			t.Logf("status=%d ct=%q client=%.240s", rr.Code, tc.contentType, client)
			t.Logf("audit=%.320s", buf.String())

			if strings.Contains(client, piiMarker) {
				t.Errorf("INVAR-1 LEAK via the non-JSON error path: raw PII reached the "+
					"client at status %d (content-type %q): %.240s", rr.Code, tc.contentType, client)
			}
			if strings.Contains(buf.String(), longSecretKey) {
				t.Errorf("INVAR-5 LEAK: raw API key in the audit log: %.200s", buf.String())
			}
			// Content-Length must be truthful after any rewrite.
			if cl := rr.Header().Get("Content-Length"); cl != "" {
				want := rr.Body.Len()
				if cl != itoaLocal(want) {
					t.Errorf("Content-Length=%q but %d bytes written", cl, want)
				}
			}
		})
	}
}

// A genuine proxy error page must still reach the client intact: redacting a
// diagnostic is fine, destroying it is not. This is the reason the non-JSON error
// path passes bodies through at all, and it must survive the fix.
func TestGenuineProxyErrorPageStillReachesTheClient(t *testing.T) {
	page := "<html><head><title>502 Bad Gateway</title></head><body>" +
		"<h1>502 Bad Gateway</h1><p>nginx/1.25.3 upstream timed out " +
		"(110: Connection timed out)</p></body></html>"

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, page)
	}))
	t.Cleanup(up.Close)

	var buf bytes.Buffer
	gw := newTestGateway(t, nil, &buf)
	gw.UpstreamURL = up.URL
	gw.Redactor = shapeRedactor{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("X-API-Key", longSecretKey)
	gw.ServeHTTP(rr, req)

	client := rr.Body.String()
	t.Logf("status=%d client=%.240s", rr.Code, client)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("the upstream error status must survive, got %d", rr.Code)
	}
	for _, want := range []string{"502 Bad Gateway", "nginx/1.25.3", "upstream timed out"} {
		if !strings.Contains(client, want) {
			t.Errorf("the diagnostic %q was lost: %s", want, client)
		}
	}
}

func itoaLocal(n int) string {
	// Local to avoid a second strconv import in this file's set.
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
