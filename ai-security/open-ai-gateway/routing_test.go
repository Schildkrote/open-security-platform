package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Schildkrote/open-ai-gateway/internal/registry"
)

// ---------------------------------------------------------------------------
// Routing tests (review finding M28 / N6).
//
// main.go previously built the mux inline, so it had ZERO test coverage and
// nothing pinned the two security-relevant routing decisions:
//
//   - N6: GET /v1/models regressed to 400 when the fail-closed body parse landed,
//     because mux.Handle("/v1/", gw) routed a bodyless GET into a POST-only
//     handler. The old code silently forwarded an empty body upstream; the fix
//     made the breakage loud, and then answered the route directly.
//   - the disclosure question that the N6 fix had to get right: /v1/models is
//     UNAUTHENTICATED, and the tool registry carries Endpoint and Scopes. Serving
//     the registry there would have been an information-disclosure bug introduced
//     by the fix itself.
//
// buildMux exists so these are testable at all.
// ---------------------------------------------------------------------------

// stubGateway records that it was reached, and never forwards anywhere.
type stubGateway struct {
	reached bool
}

func (s *stubGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.reached = true
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"stub":"gateway"}`))
}

func registryWithSecretTool(t *testing.T) *registry.Registry {
	t.Helper()
	reg := registry.New()
	reg.Register(registry.Tool{
		Name:        "internal-payments",
		Kind:        "http",
		Endpoint:    "https://payments.internal.example.corp/admin/refund",
		Risk:        registry.RiskHigh,
		Allowed:     true,
		Description: "refunds money",
		Scopes:      []string{"payments:write", "admin"},
	})
	return reg
}

func TestModelsRouteIsAnsweredNotFailedWith400(t *testing.T) {
	gw := &stubGateway{}
	mux := buildMux(gw, registry.New(), "")

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	t.Logf("GET /v1/models -> %d %s", rr.Code, rr.Body.String())

	// The N6 regression: this returned 400 "request body must be a JSON object".
	if rr.Code == http.StatusBadRequest {
		t.Errorf("N6 REGRESSION: GET /v1/models returned 400 - a bodyless GET must not " +
			"be routed into the body-parsing gateway")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("GET /v1/models = %d, want 200", rr.Code)
	}
	if gw.reached {
		t.Errorf("GET /v1/models reached the inference gateway; it must be answered by the mux")
	}

	var body struct {
		Object string `json:"object"`
		Data   []any  `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v (%s)", err, rr.Body.String())
	}
	if body.Object != "list" {
		t.Errorf("object = %q, want \"list\"", body.Object)
	}
	if body.Data == nil {
		t.Errorf("data is null; clients expect an empty array, not null")
	}
	if len(body.Data) != 0 {
		t.Errorf("data must be empty - this gateway is a policy point, not a model "+
			"catalogue, and must not advertise models no rule was written against; got %v", body.Data)
	}
}

func TestModelsRouteDoesNotDiscloseTheToolRegistry(t *testing.T) {
	reg := registryWithSecretTool(t)
	mux := buildMux(&stubGateway{}, reg, "")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	body := rr.Body.String()
	t.Logf("GET /v1/models -> %d %s", rr.Code, body)

	// /v1/models is UNAUTHENTICATED. None of the registry's internals may appear.
	for _, forbidden := range []string{
		"internal-payments",
		"payments.internal.example.corp",
		"/admin/refund",
		"payments:write",
		"refunds money",
		"high",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("DISCLOSURE: unauthenticated /v1/models leaked %q: %s", forbidden, body)
		}
	}
}

func TestModelsRouteMethodHandling(t *testing.T) {
	mux := buildMux(&stubGateway{}, registry.New(), "")

	for _, tc := range []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodHead, http.StatusOK},
		{http.MethodPost, http.StatusMethodNotAllowed},
		{http.MethodDelete, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var body string
			if tc.method == http.MethodPost || tc.method == http.MethodDelete {
				body = `{}`
			}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(tc.method, "/v1/models", strings.NewReader(body)))
			t.Logf("%s /v1/models -> %d", tc.method, rr.Code)
			if rr.Code != tc.want {
				t.Errorf("%s /v1/models = %d, want %d", tc.method, rr.Code, tc.want)
			}
		})
	}
}

// POST /v1/chat/completions must still reach the gateway - the /v1/models route
// must not shadow the inference path it sits beside.
func TestInferenceRouteStillReachesTheGateway(t *testing.T) {
	gw := &stubGateway{}
	mux := buildMux(gw, registry.New(), "")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[]}`)))

	t.Logf("POST /v1/chat/completions -> %d", rr.Code)
	if !gw.reached {
		t.Errorf("the inference route did not reach the gateway - /v1/models is shadowing it")
	}
}

func TestHealthzRoute(t *testing.T) {
	mux := buildMux(&stubGateway{}, registry.New(), "")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Errorf("GET /healthz = %d %q, want 200 \"ok\"", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// /admin/tools auth gate.
//
// Honest caveat, recorded rather than glossed: auth.Middleware treats an EMPTY
// secret as "auth disabled" (passthrough) so components work offline by default.
// That is pre-existing platform behaviour, not something this branch introduced,
// and the second subtest pins it so a future reader cannot mistake the default
// deployment for an authenticated one.
// ---------------------------------------------------------------------------

func TestAdminToolsRequiresAuthWhenASecretIsSet(t *testing.T) {
	reg := registryWithSecretTool(t)
	mux := buildMux(&stubGateway{}, reg, "test-admin-secret")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tools", nil))
	t.Logf("GET /admin/tools (secret set, no token) -> %d %s", rr.Code, rr.Body.String())

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /admin/tools = %d, want 401 when OSP_AUTH_SECRET is set", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "internal-payments") {
		t.Errorf("DISCLOSURE: /admin/tools served the registry without a token: %s", rr.Body.String())
	}
}

func TestAdminToolsIsOpenWhenNoSecretIsConfigured(t *testing.T) {
	reg := registryWithSecretTool(t)
	mux := buildMux(&stubGateway{}, reg, "")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tools", nil))
	t.Logf("GET /admin/tools (no secret) -> %d %.160s", rr.Code, rr.Body.String())

	// Documents the offline default: no secret = no auth. If this ever becomes
	// authenticated by default, this test SHOULD fail and be updated - that would
	// be a security improvement, not a regression.
	if rr.Code != http.StatusOK {
		t.Errorf("/admin/tools = %d with no secret configured; the documented offline "+
			"default is passthrough 200. If this changed deliberately, update this test.", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "internal-payments") {
		t.Errorf("the registry was not served on the open default path: %s", rr.Body.String())
	}
}
