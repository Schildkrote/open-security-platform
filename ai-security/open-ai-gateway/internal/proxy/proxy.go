// Package proxy is the gateway core: it inspects, filters, rate-limits,
// forwards and audits LLM/agent traffic.
package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Schildkrote/open-ai-gateway/internal/audit"
	"github.com/Schildkrote/open-ai-gateway/internal/policy"
	"github.com/Schildkrote/open-ai-gateway/internal/ratelimit"
	"github.com/Schildkrote/open-ai-gateway/internal/redactor"
)

// Gateway holds the dependencies for request handling.
type Gateway struct {
	UpstreamURL    string
	Engine         *policy.Engine
	Limiter        *ratelimit.Limiter
	Audit          *audit.Logger
	RedactRequest  bool // always redact request bodies (in addition to policy)
	RedactResponse bool
	Client         *http.Client
	Authorize      func(*http.Request) // optional provider auth (Phase 3 LLM connectors)
	Redactor       redactor.Redactor   // optional redaction backend (default: regex)
}

// redactor returns the configured redaction backend, defaulting to regex.
func (g *Gateway) redactor() redactor.Redactor {
	if g.Redactor != nil {
		return g.Redactor
	}
	return redactor.Regex{}
}

// noFollowClient is used when the caller did not supply a client.
//
// BL-16: the default was http.DefaultClient, which follows up to 10 redirects.
// The gateway attaches PROVIDER CREDENTIALS to the upstream request (via
// g.Authorize — e.g. a Bearer token, or Anthropic-style x-api-key), and the
// upstream is hostile-or-compromised by this project's own threat model. A 307
// from that upstream is therefore a trivially available exfiltration primitive:
// the gateway re-sends its credentialed request to an attacker-chosen collector.
//
// Go's stdlib only strips `Authorization` on a cross-HOST hop, and only since
// 1.19 — x-api-key and every other provider header survive to the attacker host.
// Relying on that behaviour is relying on a stdlib detail covering one of
// several credential headers.
//
// Redirects are refused outright instead: a model-completion endpoint has no
// legitimate reason to redirect, and http.ErrUseLastResponse surfaces the 3xx to
// the caller, which then fails closed.
var noFollowClient = &http.Client{
	CheckRedirect: noFollowRedirect,
}

// noFollowRedirect surfaces the redirect response instead of following it, so the
// gateway can treat a 3xx like any other upstream response — sweep its Location
// before auditing (BL-16) and serve it to the client — rather than silently
// re-issuing a credentialed request to an attacker-chosen host.
func noFollowRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// client returns the HTTP client used for upstream calls.
//
// BL-21: an INJECTED client is wrapped so it cannot silently re-open BL-16.
// Previously this returned g.Client verbatim and the refusal lived only in
// noFollowClient, so any caller setting a natural `&http.Client{}` got default
// redirect-following behaviour back, credential exfiltration included. Gateway and
// its Authorize hook are both exported, which makes this a live API hazard rather
// than a theoretical one — the previous comment claimed an injected client was
// "used as given so tests keep control", and that claim was false: no test or call
// site in this repo sets Client at all, so the field guarded nothing while silently
// disabling a security control. The reviewer reproduced a custom client forwarding
// BOTH Authorization and X-Api-Key verbatim to a collector after a 307 (Go strips
// only Authorization cross-host, and only since 1.19).
//
// The caller's Transport, Timeout, Jar and every other field are preserved — only
// CheckRedirect is imposed, and only when the caller left it nil. A caller who
// genuinely wants redirect handling opts in explicitly by supplying their own
// CheckRedirect, which is a deliberate decision rather than an accident of an unset
// field. Fail-safe by default: forgetting to configure redirects must not mean
// "follow them".
func (g *Gateway) client() *http.Client {
	if g.Client == nil {
		return noFollowClient
	}
	if g.Client.CheckRedirect != nil {
		// Explicit opt-in: the caller asked for specific redirect handling and owns
		// the consequence.
		return g.Client
	}
	// Shallow copy so the caller's client is not mutated behind their back and
	// repeated calls do not re-wrap it.
	wrapped := *g.Client
	wrapped.CheckRedirect = noFollowRedirect
	return &wrapped
}

// ServeHTTP implements the gateway decision pipeline.
// maxBodyBytes bounds how much of a request or response body the gateway buffers.
// Both are read fully into memory before any decision can be made, so an unbounded
// read is a memory-exhaustion vector aimed at the gateway itself.
const maxBodyBytes = 32 << 20 // 32 MiB

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Resolved before the recovery handler is registered, because that handler
	// closes over it. A closure cannot capture a variable that is not yet in
	// scope: declaring this after the defer made the panic event the one audit
	// record that could never name its caller - and for a gateway whose selling
	// point is a tamper-evident trail, the event a misbehaving Redactor produces
	// is precisely the one that must be attributable. It also sits above the
	// body-size refusal so that path is attributed too.
	apiKey := extractKey(r)

	// A misbehaving Redactor (e.g. a backend that panics on malformed input) must
	// not escape the handler. net/http recovers per connection so the process
	// survives - but the panic left ZERO audit events for a request that WAS
	// processed, and for a gateway whose selling point is a tamper-evident trail
	// that gap is itself the defect. Recovering keeps the chain complete.
	defer func() {
		if rec := recover(); rec != nil {
			// Attributed: the closure captures by reference, and the key is
			// resolved above, so the panic event can name the caller. Without
			// this the one event a misbehaving Redactor produces is the one that
			// cannot be traced.
			g.log(audit.Event{APIKey: maskKey(apiKey), Action: "error", Rule: "handler-panic",
				Reason: "recovered from panic: " + panicTypeName(rec),
				Meta:   map[string]any{"panic_type": panicTypeName(rec)}})
			http.Error(w, "internal gateway error", http.StatusInternalServerError)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		// BL-17: this returned a silent 400 with ZERO audit events, even though
		// the key was already extracted above and the panic-recovery comment
		// states the event a misbehaving component produces "is precisely the one
		// that must be attributed". A client that opens a request and aborts
		// mid-body leaves no trace at all — the BL-13 class on the request side.
		// Mirror that fix: masked key, explicit action and rule.
		g.log(audit.Event{APIKey: maskKey(apiKey), Action: "denied",
			Rule: "request-read-error", Reason: "client request body could not be read"})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		g.log(audit.Event{APIKey: maskKey(apiKey), Action: "denied", Rule: "request-too-large",
			Reason: "request body exceeds the gateway's buffering limit"})
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":  "request body too large",
			"detail": fmt.Sprintf("limit is %d bytes", maxBodyBytes),
		})
		return
	}

	// Parse the request as a generic map rather than a narrow struct. The old
	// code did `_ = json.Unmarshal(body, &req)` into a chatRequest whose message
	// content was typed `string`, and DISCARDED the error. OpenAI's multimodal
	// form sends content as an array of parts:
	//
	//	{"role":"user","content":[{"type":"text","text":"..."}]}
	//
	// That unmarshal failed, req.Messages stayed empty, and content came out
	// EMPTY - so policy ContentRe rules could not match and the redactor had
	// nothing to redact. Verified against origin/main before fixing: a deny rule
	// on "FORBIDDEN" returned 403 for plain string content but 200 for the same
	// text in multimodal form, and an email address was forwarded upstream
	// unredacted. That is a bypass-by-request-shape against a gateway whose
	// whole purpose is policy enforcement and PII removal.
	//
	// Failing closed matters here: a body we cannot inspect must not be
	// forwarded uninspected.

	// Set when the bytes the gateway sends to the CLIENT no longer match what
	// upstream returned, so validator headers describing upstream's body cannot be
	// copied verbatim.
	//
	// Only the response side needs a flag. A request-side redaction changes what
	// upstream RECEIVES, not what comes back, so it must not strip the response's
	// ETag/Last-Modified - the earlier single conflated flag did exactly that,
	// dropping validators for a response body that was byte-identical to
	// upstream's. Whether the request was rewritten is already carried by
	// ev.Redactions, so a second flag would be redundant.
	responseRewritten := false

	parsedReq, reqErr := decodeJSONObject(body)
	if reqErr != nil {
		g.log(audit.Event{APIKey: maskKey(apiKey), Action: "denied", Rule: "malformed-request",
			Reason: "request body is not a JSON object; refusing to forward uninspected content"})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "request body must be a JSON object",
			"detail": reqErr.Error(),
		})
		return
	}
	model := stringField(parsedReq, "model")
	// Only contentOK is used now. extractContent remains the SHAPE guard that
	// fails closed when the message container itself cannot be read; BL-11 moved
	// the policy view to every string in the body (see Evaluate below), so the
	// extracted text is no longer what policy reads.
	_, contentOK := extractContent(parsedReq)

	ev := audit.Event{APIKey: maskKey(apiKey), Model: model}

	// 1. Policy decision.
	//
	// BL-11: policy now evaluates EVERY string in the request body, not just the
	// messages[].content that extractContent could read. A ContentRe deny rule that
	// only saw message content was bypassable by field choice - the reviewer
	// reproduced {"model":"m","prompt":"say FORBIDDEN please"} passing a rule that
	// denied "FORBIDDEN", audited as action:"allow". allRequestStrings covers
	// prompt, metadata, tool descriptions, the user field, data URIs and object
	// keys, in a deterministic order so decisions are reproducible.
	dec := g.Engine.Evaluate(policy.Request{Model: model, Content: allRequestStrings(parsedReq), APIKey: apiKey})
	ev.Action = string(dec.Action)
	ev.Rule = dec.Rule
	ev.Reason = dec.Reason

	// If messages were present but we could not read them as text, we cannot
	// honestly say the content was inspected. Fail closed rather than forward
	// uninspected content past policy and redaction.
	// !contentOK means extractContent saw input it could not read. That is
	// sufficient on its own: it returns ok=true when messages is absent or null
	// (nothing to inspect), and ok=false both for a non-array messages container
	// and for an unreadable element or content shape. Gating this on a second
	// shape check would re-suppress the non-array container case, which is exactly
	// the bypass being closed.
	if !contentOK {
		// Record the refusal as a refusal. ev.Action still holds whatever the
		// policy engine decided - "allow" under an allow-default config - so an
		// event written here reads as a successful forward for a request that was
		// actually rejected with 400. The streaming refusal already set
		// action:"denied"; this path must agree with it or the trail misrepresents
		// its own outcome.
		ev.Action = "denied"
		ev.Rule = "unsupported-content-shape"
		ev.Reason = "message content is not in a shape the gateway can inspect"
		g.log(ev)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "message content is not in a supported shape",
			"detail": "expected a string or an array of {type:text,text:string} parts",
		})
		return
	}

	if dec.Action == policy.Deny {
		g.log(ev)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "denied by policy", "rule": dec.Rule, "reason": dec.Reason})
		return
	}

	// BL-15a: deny before forwarding when this key has already exhausted a
	// configured cumulative budget. Enforcing only after the response arrives
	// means the tokens are already spent — the upstream was already called and the
	// work already done — so "deny when a request exceeds the budget" would never
	// actually deny anything. This is the pre-flight half of enforcement.
	if g.Limiter.OverBudget(apiKey) {
		ev.Action = "denied"
		ev.Rule = "token-budget-exhausted"
		ev.Reason = "key has exhausted its configured cumulative token budget"
		g.log(ev)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "token budget exhausted",
		})
		return
	}

	// 2. Rate limit.
	if !g.Limiter.AllowRequest(apiKey, nowFn()) {
		ev.Action = "rate_limited"
		g.log(ev)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
		return
	}

	// Streaming is refused while response redaction is enabled.
	//
	// An SSE upstream response is not JSON, so the parse below fails and BOTH
	// response redaction and usage accounting are skipped: the stream is forwarded
	// to the client verbatim (any PII the model emits included) and records zero
	// tokens, which is also a budget bypass. Preserving the client's stream:true
	// field is correct in itself - dropping it silently changed what the client
	// asked for - but it opened that unredactable path. Fail closed instead of
	// silently disabling the gateway's core function; SSE-aware redaction is the
	// follow-up.
	// BL-15b: a streamed response is SSE, not a JSON object, so it can be neither
	// swept structurally nor accounted for — there is no usage figure to read. The
	// refusal therefore has to cover BOTH guarantees the gateway claims, not just
	// redaction: with redact_response:false AND a budget configured, the previous
	// condition passed the stream through verbatim while recording zero tokens,
	// which is the exact budget bypass the refusal exists to prevent (reviewer
	// probe P2: 5/5 streamed completions served against a 100-token budget).
	//
	// Streaming is still allowed when the operator has claimed NEITHER guarantee
	// (redaction off and no budget configured) — that is an explicit, honest
	// configuration, not a bypass, and refusing it would break a core LLM-gateway
	// feature for deployments that never asked for redaction or budgeting.
	streamUnsafe := g.RedactResponse || g.Limiter.HasBudget()
	if streamUnsafe && wantsStreaming(parsedReq) {
		ev.Action = "denied"
		ev.Rule = "streaming-unsupported"
		ev.Reason = "streaming responses cannot be redacted or accounted for; refused"
		g.log(ev)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "streaming is not supported while response redaction is enabled",
			"detail": streamingRefusalDetail(g),
		})
		return
	}

	// 3. Request redaction.
	//
	// Redaction rewrites the ORIGINAL body as a generic map rather than
	// re-marshalling a narrow struct. RedactRequest defaults to true, so the old
	// `body, _ = json.Marshal(req)` path silently dropped every field the client
	// sent beyond model+messages: stream, temperature, top_p, max_tokens, stop,
	// n, tools, tool_choice, response_format. A streaming client would receive a
	// non-streaming upstream call and tool-calling clients would lose their tool
	// schema, with no error anywhere.
	//
	// Content is redacted IN PLACE per message/per text part, never by writing
	// one flattened string back into a single message: flattening would destroy a
	// multimodal message's image parts and collapse several messages into one, so
	// what reached upstream would no longer mean what the client sent.
	if g.RedactRequest || dec.Action == policy.Redact {
		rewritten, kinds, err := redactRequestContent(parsedReq, g.redactor())
		switch {
		case err != nil:
			// Sensitive content WAS found but the body could not be rewritten.
			// Forwarding the original would leak PII upstream while the audit
			// trail claims it was redacted, so fail closed instead.
			ev.Action = "redaction_failed"
			ev.Redactions = append(ev.Redactions, kinds...)
			ev.Meta = map[string]any{"redaction": "rewrite_failed"}
			g.log(ev)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": "request could not be redacted; refusing to forward it",
			})
			return
		case len(kinds) > 0:
			body = rewritten
			ev.Redactions = append(ev.Redactions, kinds...)
		}
	}

	// 4. Forward upstream.
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.UpstreamURL, bytes.NewReader(body))
	if err != nil {
		// BL-13 sibling: same hole as the unreachable-upstream path below. The
		// reviewer judged this unreachable with a configured URL, which is right
		// for a well-formed config - but a malformed g.UpstreamURL reaches it, and
		// a processed-and-failed request that writes no event is a hole in a
		// tamper-evident trail either way. err.Error() can echo the configured
		// URL, so the reason is fixed text and the key is masked.
		ev.Action = "upstream_error"
		ev.Rule = "upstream-request-invalid"
		ev.Reason = "upstream request could not be constructed"
		setMeta(&ev, "upstream", "request_construction_failed")
		g.log(ev)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	if g.Authorize != nil {
		g.Authorize(upReq)
	}
	resp, err := g.client().Do(upReq)
	if err != nil {
		// BL-13: this path wrote NO audit event, so a request that had already
		// passed policy and rate limiting produced a 502 and an empty trail. For a
		// product whose selling point is a tamper-evident record, a
		// processed-and-failed request with zero events is a hole in the trail -
		// the same class the handler-panic fix closed. Mirror the read-error path
		// below. The transport error text can contain the upstream URL and DNS
		// detail, so it is recorded as a fixed reason rather than err.Error(); the
		// key is masked like every other event.
		ev.Action = "upstream_error"
		ev.Rule = "upstream-unreachable"
		ev.Reason = "upstream connection could not be established"
		setMeta(&ev, "upstream", "connect_failed")
		g.log(ev)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// The read error must not be discarded: a truncated upstream body is not the
	// same as a complete one, and forwarding partial bytes while announcing their
	// length is exactly how the original Content-Length bug presented.
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if readErr != nil {
		ev.Action = "upstream_error"
		setMeta(&ev, "upstream", "response_read_failed")
		g.log(ev)
		http.Error(w, "upstream response could not be read", http.StatusBadGateway)
		return
	}
	if len(respBody) > maxBodyBytes {
		ev.Action = "upstream_error"
		setMeta(&ev, "upstream", "response_too_large")
		g.log(ev)
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}

	// BL-16: a redirect is refused, not followed. With noFollowClient the 3xx is
	// surfaced here rather than silently re-requested against another host with
	// our provider credentials attached. A completion endpoint has no legitimate
	// reason to redirect, and following one would hand a hostile upstream an
	// exfiltration primitive for the gateway's own credentials. Fail closed and
	// say so in the audit trail.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		ev.Action = "denied"
		ev.Rule = "upstream-redirect"
		// The Location is upstream-controlled and may itself carry the reflected
		// credential or PII, so it is redacted before entering the audit record.
		// Recording a raw redirect target would make the trail a leak channel.
		if loc != "" {
			cleaned, _ := g.redactor().Redact(loc)
			setMeta(&ev, "location", cleaned)
		}
		ev.Reason = "upstream returned a redirect; refused rather than re-sending credentials"
		g.log(ev)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "upstream attempted a redirect, which the gateway refuses to follow",
		})
		return
	}

	// 5. Response redaction + usage accounting.
	//
	// The response is handled as a generic map rather than a narrow struct on
	// purpose. Redaction used to unmarshal into a narrow struct (choices[].message
	// + usage.total_tokens only) and re-marshal that, which silently DROPPED
	// every other upstream field — id, object, created, model, system_fingerprint,
	// choices[].index and choices[].finish_reason, and the prompt_tokens /
	// completion_tokens breakdown. Clients that read finish_reason to detect
	// truncation, or model for routing/logging, got an OpenAI-incompatible
	// response. RedactResponse defaults to true, so this was the normal path.
	// A map round-trip preserves unknown fields and cannot drift when upstream
	// adds one.
	var parsed map[string]any
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		// A response that is not JSON cannot be swept structurally, so it is swept
		// as TEXT instead.
		//
		// This path used to branch on the status code: a 2xx non-JSON body was
		// refused with 502, while an error body was passed through untouched on the
		// reasoning that an upstream 502 page is diagnostic rather than model
		// output. The reasoning is right about real proxy error pages and wrong
		// about the security property, because it makes the decision to inspect
		// bytes depend on a value the UPSTREAM controls. A compromised or
		// misconfigured upstream only has to answer 500 text/plain - or omit the
		// content type entirely - and its body reaches the client uninspected.
		// Verified: a text/plain 500 carrying an email address was served verbatim
		// through text/html, application/xml and no-content-type variants alike.
		//
		// Redacting the raw text closes that without costing the diagnostic. The
		// redactor operates on text; running it over an error page leaves
		// "502 Bad Gateway / nginx / upstream timed out" intact and removes only
		// what looks like PII. A pinned test asserts a real nginx page survives
		// byte-for-byte.
		//
		// Binary bodies are the one case text redaction cannot serve, so they fail
		// closed at EVERY status rather than at 2xx only. "Not valid UTF-8" is the
		// test: a regex pass over image or audio bytes cannot find PII and would
		// corrupt the payload, so there is nothing honest to do but refuse.
		setMeta(&ev, "response", "unparseable")
		if g.RedactResponse {
			// A 2xx non-JSON body is refused, and the reason is ACCOUNTING, not
			// redaction. A successful completion is a billable, rate-limited
			// action, but no usage figure can be extracted from a body that is not
			// JSON - so serving it would record a success at zero tokens. That is
			// the BL-2 budget-bypass class: completions that escape the token
			// budget. The round-1 fix chose fail-loud accounting over recording
			// zero, and this path has to be consistent with that. The body never
			// reaches the client, so nothing leaks by refusing it.
			if isSuccessfulStatus(resp.StatusCode) {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "unparseable_success_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream returned a successful response that could not be redacted",
				})
				return
			}

			// A non-2xx body is diagnostic, not a billable completion, so there is
			// no accounting expectation and it SHOULD reach the client - an
			// upstream 429/502 page is exactly what the caller needs to debug the
			// failure. But "pass it through" must not mean "pass it through
			// UNREDACTED", which is what this branch did before and is how a
			// compromised upstream could leak model output under a 500 text/plain.
			// Redact the text and serve it with its status intact: a real nginx
			// error page survives byte-for-byte, only PII is removed.
			//
			// Binary is the one case text redaction cannot serve - a regex pass
			// over image or audio bytes neither finds PII nor leaves the payload
			// decodable - so it fails closed at every status. "Not valid UTF-8" is
			// the test.
			if !utf8.Valid(respBody) {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "uninspectable_binary_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream returned a non-UTF-8 response that could not be redacted",
				})
				return
			}
			cleaned, found := g.redactor().Redact(string(respBody))
			for _, k := range found {
				ev.Redactions = append(ev.Redactions, "resp:"+k)
			}
			if cleaned != string(respBody) {
				respBody = []byte(cleaned)
				responseRewritten = true
			}
			// No usage figure is extractable from a non-JSON body, so token
			// accounting stays empty. Recorded rather than silently omitted. An
			// error response is not a billable completion, so zero tokens here is
			// correct rather than a bypass.
			setMeta(&ev, "usage", "unparseable")
		} else {
			// BL-20b: with response redaction OFF this branch was skipped entirely,
			// so a non-JSON completion was served with NO accounting entry at all —
			// neither a usage figure nor the "unparseable" diagnostic. The audit
			// record simply omitted the fact that accounting was impossible, which is
			// the exact "an exemption that leaves no diagnostic is indistinguishable
			// from a silent hole" principle this branch already applies to opaque
			// binaries (BL-9). Record it regardless of the redaction setting.
			setMeta(&ev, "usage", "unparseable")
		}

		// BL-20 (non-JSON twin): charge an estimate here too, and deliberately NOT
		// gated on g.RedactResponse. The budget and the redactor are independent
		// guarantees; gating accounting on a redaction setting is precisely how the
		// reviewer's TestR8_VULN_NonJSONBodyBypassesBudgetWithRedactionOff worked —
		// turn redaction off and the bypass reappears. A non-JSON 2xx is a completion
		// the client will act on, so it is billable; the estimate is the only figure
		// available. See the JSON-path comment for why estimation beats refusal.
		if isSuccessfulStatus(resp.StatusCode) {
			est := estimateTokens(respBody)
			ev.Tokens = est
			setMeta(&ev, "usage", "estimated")
			if !g.Limiter.RecordUsage(apiKey, est) {
				setMeta(&ev, "budget", "exceeded")
				ev.Action = "denied"
				ev.Rule = "token-budget-exceeded"
				ev.Reason = "estimated usage for an unaccounted completion exceeded the configured cumulative token budget"
				g.log(ev)
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"error": "token budget exceeded",
				})
				return
			}
		}
	} else {
		if g.RedactResponse {
			// redactResponse re-marshals the parsed map, so the served bytes no
			// longer match what upstream sent even when nothing was redacted.
			// Validator headers describing the upstream body must not be copied.
			before := respBody
			redacted, kinds, opaqueSkipped, err := redactResponse(parsed, g.redactor())
			if opaqueSkipped > 0 {
				// BL-9: an exemption that leaves no diagnostic is indistinguishable
				// from a silent hole. Record that N positions were skipped as
				// verified-opaque binary so the trail accounts for every byte.
				setMeta(&ev, "redaction", "opaque_skipped")
				setMeta(&ev, "opaque_skipped", opaqueSkipped)
			}

			// Record the redactions the sweep applied and serve the re-encoded
			// map. There is no status-code branch here any more, and that is
			// deliberate: the previous version failed closed on 2xx and passed
			// error bodies through, so the gateway trusted an UPSTREAM-CONTROLLED
			// status code for a security decision. A sweep that inspects every
			// string needs no such branch - the only failure left is "could not
			// marshal the result", which fails closed for every status alike.
			//
			// Error diagnostics still survive: the sweep redacts PII out of the
			// error object and leaves its text alone, and resp.StatusCode is
			// written below, so a 429 stays a 429 with its message intact.
			if err != nil {
				ev.Action = "redaction_failed"
				setMeta(&ev, "redaction", "unreencodable_response")
				g.log(ev)
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream response could not be redacted",
				})
				return
			}
			respBody = redacted
			ev.Redactions = append(ev.Redactions, kinds...)

			if !bytes.Equal(before, respBody) {
				responseRewritten = true
			}
		}
		tokens, ok := totalTokens(parsed)
		if !ok {
			// No usable usage figure: say so in the audit record instead of
			// recording zero and letting a budget look unconsumed.
			setMeta(&ev, "usage", "unparseable")

			// BL-20: charge an ESTIMATE rather than recording zero. Omitting `usage`
			// is entirely within the upstream's control, so before this a
			// hostile-or-compromised provider defeated the cumulative token budget by
			// simply never sending a usage figure — the reviewer measured 5/5
			// requests served 200 against BudgetTokens=100 with `tokens recorded=0`,
			// which is the non-streaming twin of the BL-15b streaming bypass whose
			// own comment states the principle ("an unaccountable completion under an
			// active budget is a bypass").
			//
			// WHY ESTIMATE AND NOT REFUSE. Refusing an unaccountable completion is the
			// stricter option and it is WRONG HERE, for three reasons I verified
			// rather than assumed:
			//   1. BudgetTokens defaults to 1_000_000 in internal/config/config.go
			//      and is not exposed via env or flag, so a budget is ACTIVE IN THE
			//      DEFAULT CONFIGURATION. A refusal would therefore break the gateway
			//      out of the box.
			//   2. Many real providers legitimately omit `usage` on some responses.
			//      Turning that into a 502 trades a bounded accounting gap for a
			//      broken primary function.
			//   3. It broke 42 existing tests, including
			//      TestChokepointInvariantAcrossTheWholeShapeSpace — the 1106-case
			//      shape sweep that is this branch's core security guarantee. A fix
			//      that disables the suite protecting the chokepoint is not a fix.
			//
			// Estimating keeps both properties that matter: the completion still
			// reaches the client (no functional regression), and consumption is still
			// CHARGED, so the budget bounds spend approximately instead of not at all.
			// The audit record says `"usage":"estimated"` rather than `"unparseable"`
			// so nobody mistakes the figure for a real one — the BL-9 principle that
			// an exemption must leave a diagnostic.
			//
			// GATED ON SUCCESS. Only a 2xx is a billable completion. An upstream 429
			// or 500 whose body happens to be JSON without a usage figure is an ERROR,
			// not work the caller received, so it must not be charged — that is the
			// invariant the pre-BL-20 code stated outright ("an error response is not a
			// billable completion, so zero tokens here is correct rather than a
			// bypass") and which a first cut of this fix broke by estimating at every
			// status. Billing for a failed request would make the budget punish clients
			// for upstream errors, which is its own kind of lie.
			//
			// This is ACCOUNTING, not a security decision on the status code, so it does
			// not reintroduce the antipattern rounds 1-5 were rejected for: redaction
			// above ran regardless of status, and what the status decides here is only
			// whether the caller consumed something billable.
			if isSuccessfulStatus(resp.StatusCode) {
				est := estimateTokens(respBody)
				ev.Tokens = est
				setMeta(&ev, "usage", "estimated")
				if !g.Limiter.RecordUsage(apiKey, est) {
					// Post-flight enforcement, same shape as the real-usage path below.
					// Nothing has been written to w yet.
					setMeta(&ev, "budget", "exceeded")
					ev.Action = "denied"
					ev.Rule = "token-budget-exceeded"
					ev.Reason = "estimated usage for an unaccounted completion exceeded the configured cumulative token budget"
					g.log(ev)
					writeJSON(w, http.StatusTooManyRequests, map[string]any{
						"error": "token budget exceeded",
					})
					return
				}
			} else {
				// Diagnostic, not billable: record that no figure was available and
				// charge nothing.
				setMeta(&ev, "usage", "unparseable")
			}
		} else {
			ev.Tokens = tokens
			if !g.Limiter.RecordUsage(apiKey, tokens) {
				// BL-15c: RecordUsage's false used to be recorded as a
				// meta diagnostic and then IGNORED — the over-budget completion
				// was served in full with a 200. That made the budget decorative
				// in every configuration (reviewer probe P3: 3 requests x 1000
				// tokens against BudgetTokens=100 all returned 200). The
				// post-flight half of enforcement: fail closed.
				//
				// Nothing has been written to w yet (headers and body are emitted
				// after this block), so a clean 429 is still possible. The tokens
				// are already spent upstream, which is why BL-15a denies
				// pre-flight; this is the backstop for the request that crosses
				// the line.
				setMeta(&ev, "budget", "exceeded")
				ev.Action = "denied"
				ev.Rule = "token-budget-exceeded"
				ev.Reason = "response usage exceeded the configured cumulative token budget"
				g.log(ev)
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"error": "token budget exceeded",
				})
				return
			}
		}
	}

	// Headers listed in the upstream's Connection header are hop-by-hop for this
	// connection specifically (RFC 9110 7.6.1) and must not be forwarded, even
	// though their names are not in the static isHopByHop set.
	connListed := connectionListedHeaders(resp.Header)

	// BL-12: headers are bytes the gateway serves to the client, so the claim
	// "no branch serves uninspected bytes" was false while header VALUES passed
	// through verbatim. The reviewer reproduced an upstream 200 carrying
	// X-Model-Output: <email> reaching the client at every status.
	//
	// The scope is deliberate: only NON-STANDARD headers are redacted, and only
	// when response redaction is enabled. Standard headers are protocol metadata
	// the client needs to interpret the response - running a PII regex over a Date
	// or a Cache-Control could break content negotiation for no security gain, and
	// neither is model output. Custom X-*/provider-specific headers are exactly
	// where an upstream surfaces model or user data, which is what a PII regex is
	// for. isNonStandardHeader is a POSITIVE list of names to spare, so an unknown
	// header falls through to being swept rather than through to being served.
	for k, vs := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if isHopByHop(k) || connListed[ck] {
			continue
		}
		for _, v := range vs {
			out := v
			if g.RedactResponse && isNonStandardHeader(ck) {
				cleaned, found := g.redactor().Redact(v)
				if len(found) > 0 {
					out = cleaned
					for _, f := range found {
						ev.Redactions = append(ev.Redactions, "resp_hdr:"+f)
					}
					responseRewritten = true
				}
			}
			w.Header().Add(k, out)
		}
	}
	g.log(ev)

	// Validators describe a specific body. Forwarding upstream's ETag (or
	// Last-Modified) alongside a rewritten body would let a client cache the
	// redacted bytes under an identity that maps to the unredacted ones, and
	// could serve them back from cache with no gateway in the path at all.
	if responseRewritten {
		w.Header().Del("Etag")
		w.Header().Del("Last-Modified")
		w.Header().Set("Cache-Control", "no-store")
	}
	// The body may have been rewritten above, so upstream's Content-Length no
	// longer describes it. Copying it verbatim made the gateway announce more
	// bytes than it wrote, and clients aborted the transfer as truncated
	// (curl CURLE_PARTIAL_FILE / rc=18) despite a complete JSON body. Setting it
	// from the final length keeps the header truthful; net/http would otherwise
	// fall back to chunked encoding.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// hop-by-hop headers must not be forwarded by a proxy (RFC 9110 §7.6.1), and
// Content-Length is handled explicitly by the caller because the body may be
// rewritten.
func isHopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length":
		return true
	}
	return false
}

// connectionListedHeaders parses the Connection header and returns the set of
// header names it declares hop-by-hop, canonicalised. A proxy must not forward
// those (RFC 9110 7.6.1); they are connection-scoped rather than
// payload-scoped, so upstream naming them is not an instruction to pass them on.
func connectionListedHeaders(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out[http.CanonicalHeaderKey(name)] = true
			}
		}
	}
	return out
}

// redactResponse redacts model output in place within parsed and returns the
// re-marshalled body, the redaction kinds applied, and an error only if the
// result cannot be marshalled.
//
// It is a TOTAL SWEEP, not a shape-aware walker, and that difference is the
// entire point. Four successive review rounds each found PII leaving the gateway
// through a shape the previous fix had not enumerated: content as a parts array,
// a messages container that was an object, delta.content, legacy choices[].text,
// and message.text. Each fix added the newly-named shapes to a hand-maintained
// list, so the list was always one review behind. An enumerated walker can only
// ever be as complete as its author's imagination.
//
// A sweep needs no imagination. encoding/json decodes into exactly six Go types
// (nil, bool, float64, string, []any, map[string]any), so a switch over those six
// is exhaustive by construction: every string anywhere in the document is
// inspected, regardless of container, nesting depth or key name. No shape can hide
// a value, because no shape is consulted.
//
// A consequence worth stating: the caller no longer needs the upstream STATUS
// CODE to make a security decision. The previous version failed closed on 2xx and
// passed error bodies through, so the gateway trusted an upstream-controlled
// status code for a security decision and a compromised upstream could try to get
// model output served under a non-2xx label. That attack surface is gone, because
// no branch serves uninspected bytes any more.
//
// Keys in opaqueKeys may be skipped, but only when the VALUE verifies as base64
// (see isOpaqueBinary), and every skip is counted and returned so the caller can
// record that content was left uninspected. An exemption is not a hole only if it
// is validated and logged.
func redactResponse(parsed map[string]any, r redactor.Redactor) ([]byte, []string, int, error) {
	c := &sweepCtx{r: r, prefix: "resp"}
	sweepValue(parsed, c)
	body, err := marshalMap(parsed)
	if err != nil {
		return nil, c.kinds, c.opaqueSkipped, err
	}
	return body, c.kinds, c.opaqueSkipped, nil
}

// opaqueKeys name fields whose payload is binary rather than natural language,
// where running a PII regex is both wasteful and liable to mangle data the client
// cannot decode. Membership is a HINT, not a grant: see isOpaqueBinary.
var opaqueKeys = map[string]bool{
	"b64_json": true,
}

// isOpaqueBinary decides whether a value under an opaqueKeys name may skip the
// sweep, and it decides by CONTENT rather than by key name.
//
// BL-9: the exemption used to fire on the key alone, at any depth, for any value
// type. That made {"b64_json":"jane.doe@example.com"} - and the same PII under
// b64_json as an object, an array, or a deep subtree - be served verbatim, with
// nothing recorded in the audit event. It was a one-entry hand-maintained list of
// uninspectable positions, i.e. enumeration reintroduced inside the fix for
// enumeration, which is the exact defect this branch exists to remove.
//
// So the skip requires the value to be a string that actually IS base64: it must
// decode and re-encode to itself. A non-string under b64_json cannot be a binary
// payload at all, and a string that does not round-trip is not opaque data -
// either way it gets swept like everything else. All four standard encodings are
// tried so a genuine image or audio payload using URL-safe or unpadded base64 is
// not corrupted by over-redaction.
func isOpaqueBinary(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		raw, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if enc.EncodeToString(raw) == s {
			return true // round-trips: genuinely opaque binary
		}
	}
	return false
}

// sweepCtx carries what a total sweep accumulates, so the SAME traversal serves
// both directions and neither can drift from the other.
//
// prefix records which way the bytes were flowing: "resp" for upstream->client
// and "req" for client->upstream. The audit trail has to be able to tell them
// apart, because a redaction that never reached the client is not evidence the
// client was protected, and vice versa.
type sweepCtx struct {
	r             redactor.Redactor
	kinds         []string
	opaqueSkipped int
	prefix        string
}

func (c *sweepCtx) found(kind string) {
	c.kinds = append(c.kinds, c.prefix+":"+kind)
}

// sweepValue redacts every string in a JSON-decoded value, in place, and returns
// the (possibly replaced) value. Strings are immutable in Go, so containers
// reassign their children.
//
// BL-10: object KEYS are swept, not just values. A key is a string in the decoded
// document and json.Marshal re-emits it verbatim, so a compromised upstream could
// ship PII as a key ({"jane.doe@example.com":"v"}) and the client would receive it
// raw. "Every string anywhere in the document" is false for keys unless keys are
// swept.
//
// Renaming happens in a second pass: adding or deleting map entries while ranging
// over that same map is not safe in Go, so renames are collected and applied after
// the range completes. Two distinct keys can redact to the SAME string, which
// would silently drop one entry, so collisions get a numeric suffix and both are
// preserved.
//
// The default branch is a deliberate no-op rather than an error: encoding/json
// cannot produce a seventh type when decoding into any, so reaching it would mean
// a future change to how the body is decoded. json.Number is handled explicitly
// for that reason - it is a string type and a numeric literal cannot carry PII,
// but letting it fall through to default would leave the assumption unstated.
func sweepValue(v any, c *sweepCtx) any {
	switch tv := v.(type) {
	case nil, bool, float64:
		return v
	case json.Number:
		// A numeric literal. Not natural language, cannot carry PII.
		return v
	case string:
		cleaned, found := c.r.Redact(tv)
		for _, k := range found {
			c.found(k)
		}
		return cleaned
	case []any:
		for idx, el := range tv {
			tv[idx] = sweepValue(el, c)
		}
		return tv
	case map[string]any:
		// Pass 1: sweep values, collect key renames without mutating the map.
		type rename struct{ from, to string }
		var renames []rename
		for k, val := range tv {
			if opaqueKeys[k] && isOpaqueBinary(val) {
				// Genuinely opaque binary, verified by CONTENT. Record the skip so
				// the trail shows something was left uninspected and where - an
				// exemption that leaves no diagnostic is indistinguishable from a
				// silent hole (the BL-8/N1 class).
				c.opaqueSkipped++
				c.found("opaque_skipped")
				continue
			}
			tv[k] = sweepValue(val, c)
			if ck, found := c.r.Redact(k); len(found) > 0 && ck != k {
				// Record the kinds for the KEY redaction too. Discarding them here
				// would make the audit trail claim nothing was redacted while PII
				// was in fact removed from a key - the reviewer's N1 finding
				// ("string case discards found kinds") reborn one level up. It is
				// worse than a telemetry bug: redactRequestContent returns
				// (nil,nil,nil) when kinds is empty, so a request whose ONLY PII
				// sat in a key would not be rewritten at all and would be forwarded
				// to the upstream provider verbatim.
				for _, f := range found {
					c.found(f)
				}
				renames = append(renames, rename{k, ck})
			}
		}
		// Pass 2: apply renames now that ranging is finished.
		for _, rn := range renames {
			val, exists := tv[rn.from]
			if !exists {
				continue
			}
			to := rn.to
			// Preserve both entries if two keys redacted to the same string;
			// silently overwriting would drop data the client asked for.
			for n := 2; ; n++ {
				if _, clash := tv[to]; !clash {
					break
				}
				to = rn.to + "_" + strconv.Itoa(n)
			}
			delete(tv, rn.from)
			tv[to] = val
		}
		return tv
	default:
		return v
	}
}

// collectStrings gathers every string in a JSON-decoded value, keys included, in
// document order. It exists for the policy engine (BL-11): a ContentRe deny rule
// that only saw messages[].content could be bypassed by putting the forbidden text
// in ANY other field - prompt, metadata.user_email, tools[].function.description,
// the top-level user field, an image_url data URI, or an object key. Feeding
// policy the concatenation of every string means the rule cannot be dodged by
// field choice, which is the request-side analogue of the response sweep.
//
// Keys are included because a key is attacker-chosen text that reaches upstream.
func collectStrings(v any, out *[]string) {
	switch tv := v.(type) {
	case string:
		*out = append(*out, tv)
	case []any:
		for _, el := range tv {
			collectStrings(el, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic: map iteration order is randomised
		for _, k := range keys {
			*out = append(*out, k)
			collectStrings(tv[k], out)
		}
	}
}

// allRequestStrings returns every string in a request body, joined for policy
// evaluation. Deterministic ordering matters: policy decisions must be
// reproducible, and Go randomises map iteration.
func allRequestStrings(parsed map[string]any) string {
	var parts []string
	collectStrings(parsed, &parts)
	return strings.Join(parts, "\n")
}

// estimateTokens derives a conservative token estimate from a response body when
// the upstream withheld its own usage figure (BL-20). It exists so that omitting
// `usage` cannot make a completion free against the cumulative token budget.
//
// It is an APPROXIMATION and is recorded in the audit trail as `"usage":"estimated"`
// so nobody mistakes it for a real figure. The heuristic charges for the whole
// response body at roughly one token per 4 bytes, which is the widely used
// order-of-magnitude ratio for English text, plus a floor of 1 so a tiny body is
// never charged as zero.
//
// Two properties are deliberately favoured over accuracy:
//
//   - MONOTONIC: a bigger body always costs at least as much as a smaller one, so a
//     provider cannot shrink its bill by reformatting.
//   - CONSERVATIVE: over-charging by a small factor is a bounded, visible
//     accounting error that an operator can raise the budget for; under-charging to
//     zero is the bypass this closes.
//
// It is NOT a substitute for real usage accounting — when `usage` is present,
// totalTokens() reads the provider's own figure and this is not called.
func estimateTokens(body []byte) int64 {
	const bytesPerToken = 4
	n := int64(len(body)) / bytesPerToken
	if n < 1 {
		n = 1
	}
	if n > math.MaxInt32 {
		// A 32 MiB body (maxBodyBytes) cannot approach this, but clamping keeps the
		// figure sane for any future caller and cannot overflow the budget
		// accumulator.
		n = math.MaxInt32
	}
	return n
}

// isNonStandardHeader reports whether a canonical header name should have its VALUE
// swept. BL-12 redacts the values of everything this returns true for.
//
// The list is a POSITIVE list of names to SPARE. A negative list of names to redact
// would be the enumeration mistake this branch exists to remove: any header nobody
// thought of would fall through unswept.
//
// THE CRITERION, CORRECTED TWICE.
//
// Round 8 spared any header that was "part of the HTTP protocol vocabulary", on the
// assumption that such values are stack-generated rather than origin-authored. BL-22
// removed six headers (Location, Content-Location, Content-Disposition, Warning,
// Server, Etag) because that assumption is false for URI and free-text headers.
//
// Round 9 showed the criterion was STILL wrong, and named the fallacy precisely:
// inferring a value's provenance from the header NAME is the same error as inferring
// its safety from the STATUS CODE. A status the upstream controls cannot decide
// whether its value is safe — and symmetrically, neither can a name. Nothing validates
// the grammar of a Vary, Via, Retry-After, X-Request-Id, Openai-Organization, Cf-Ray
// or Content-Type boundary parameter; a hostile origin sets those bytes. The reviewer
// reproduced thirteen spared headers carrying detector-recognisable PII to the client
// verbatim, plus Content-Type: multipart/form-data; boundary=<email>.
//
// So the criterion is now: spare a header ONLY if its value is numeric, date-grammar,
// or a closed vocabulary the origin cannot extend with arbitrary text. Everything else
// is swept.
//
// WHY THIS DOES NOT BREAK INTEROP — the argument that kept the old list alive, and why
// it was wrong. The sweep is SURGICAL: it rewrites a value only when the redactor
// reports a finding, so Content-Type: application/json and
// X-Ratelimit-Remaining-Tokens: 12345 pass through BYTE-IDENTICAL. Sparing those
// headers therefore bought nothing for legitimate traffic while leaving an unswept
// channel for hostile traffic. The only values that change are ones a detector
// recognises as a credential or PII — and if an origin puts an email address in its
// multipart boundary, redacting it and breaking that parse is the correct fail-safe
// outcome, not a regression.
//
// HONEST RESIDUAL COST: a legitimate correlation id that happens to match a detector
// (an id containing an '@', or one shaped like a 40-char SSWS token) will be mangled
// and that trace link breaks. Accepted deliberately — mangling a suspicious identifier
// is cheaper than handing a hostile origin an unswept text channel, and clean ids are
// unaffected.
//
// Removing a name from a SPARE list means MORE sweeping, so every step in this
// direction is fail-safe.
func isNonStandardHeader(canonical string) bool {
	switch canonical {
	case
		// Numeric or fixed-format values the origin cannot use as a text channel
		// without breaking the protocol contract it is declaring.
		"Content-Length",                   // integer byte count
		"Age",                              // integer seconds
		"Content-Range",                    // "bytes 0-99/1000"
		"Date", "Last-Modified", "Expires", // HTTP-date grammar, stack-generated
		"Transfer-Encoding", // closed vocabulary: chunked
		// CORS policy: breaking these breaks the browser, and their values are a
		// constrained vocabulary (an origin, or a header/method name).
		"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
		"Access-Control-Allow-Headers", "Access-Control-Allow-Methods",
		"Access-Control-Expose-Headers", "Access-Control-Max-Age",
		// Security-policy directives: closed vocabularies.
		"Strict-Transport-Security", "X-Content-Type-Options",
		"X-Frame-Options", "X-Xss-Protection", "Referrer-Policy":
		return false
	}
	return true
}

// isSuccessfulStatus reports whether a status code denotes success.
//
// It is used for exactly ONE decision, and it is important to be precise about
// which: whether a non-JSON 2xx body may be served at all. It is NOT used to
// decide whether to redact - redaction now happens at every status, so no
// security property depends on a value the upstream controls. That distinction is
// the whole difference between this and the round-3 bug, where the status code
// chose whether bytes were inspected at all.
func isSuccessfulStatus(code int) bool {
	return code >= 200 && code < 300
}

// marshalMap re-marshals a decoded response. Failure is returned rather than
// papered over with the original bytes.
func marshalMap(parsed map[string]any) ([]byte, error) {
	out, err := json.Marshal(parsed)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func setMeta(ev *audit.Event, key string, value any) {
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta[key] = value
}

// totalTokens extracts usage.total_tokens, tolerating the integer types encoding/
// json produces (float64 for a generic decode).
func totalTokens(parsed map[string]any) (int64, bool) {
	usage, ok := parsed["usage"].(map[string]any)
	if !ok {
		return 0, false
	}
	switch v := usage["total_tokens"].(type) {
	case float64:
		// Clamp rather than rely on int64(float64) conversion, whose result Go
		// leaves implementation-defined for out-of-range values. On amd64/arm64
		// it saturates to MaxInt64, which happens to be safe (budget exceeded),
		// but a hostile or buggy upstream should not depend on that.
		if v != v { // NaN
			return 0, false
		}
		if v > math.MaxInt64 {
			return math.MaxInt64, true
		}
		if v < 0 {
			return 0, false
		}
		return int64(v), true
	case int64:
		return clampUsage(v)
	case int:
		return clampUsage(int64(v))
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return clampUsage(n)
	case string:
		// Some upstreams emit usage figures as JSON strings. Refusing to parse
		// them silently recorded zero tokens and skipped the budget check, which
		// is an accounting bypass rather than a formatting quirk.
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return clampUsage(n)
	}
	return 0, false
}

// clampUsage is the single gate every non-float64 usage figure passes through.
//
// NB-1 (round 9): `total_tokens: "-5000"` was PARSED, TRUSTED and ADDED to the
// caller's bucket. Because a negative figure CREDITS the budget, a hostile upstream
// could grant unlimited free completions under any budget — the review measured
// 10/10 requests served against BudgetTokens=10 with tokens-recorded=-10000000.
//
// The float64 case already had this guard (`if v < 0 { return 0, false }`), and the
// string case was added later without it. That is the enumeration failure mode again,
// one door behind: fixing only the string case would have left int64, int and
// json.Number equally exposed. So the check lives in ONE function that every
// non-float path calls, and a new numeric case cannot be added without going
// through it.
//
// A negative figure is REJECTED (ok=false), not clamped to zero. Recording zero
// would claim the gateway understood a figure that is nonsense, and would silently
// treat a hostile upstream's garbage as a legitimate free request. Rejecting routes
// it to the "unparseable" accounting path, which charges an estimate instead — so a
// hostile upstream that sends negative usage gets charged for its traffic rather than
// credited for it.
func clampUsage(v int64) (int64, bool) {
	if v < 0 {
		return 0, false
	}
	return v, true
}

// log is the audit CHOKEPOINT. Every event the gateway emits passes through here,
// so redaction of audit free text is enforced structurally instead of relying on
// each call site remembering to do it.
//
// BL-14: the audit record was itself an unredacted egress channel, two ways.
// (i) ev.Model was read from the RAW request before any sweep, so a request
// naming model "jane.doe@example.com" was served a correctly redacted body while
// the tamper-evident log recorded the email verbatim — and because Model feeds
// the chain hash, deleting it changes the record's hash, making that leak
// structural rather than cosmetic. (ii) The panic path interpolated the recovered
// VALUE into ev.Reason, so a Redactor panicking with request content in its
// message wrote that content to the log.
//
// Both are closed here for every site at once, so a NEW call site cannot re-open
// them — which is the point of a chokepoint over another per-site patch.
//
// Fields swept: Model, Reason, and Meta (several sites put upstream-derived text
// in Meta, e.g. a refused redirect's Location). Fields deliberately EXEMPT:
// Action and Rule are closed sets of gateway-chosen constants; Redactions are
// KIND labels ("req:EMAIL"), not content; APIKey is already masked by maskKey;
// Tokens and the hashes are numeric/structural. Exempting them is what stops the
// sweep from corrupting the trail's own vocabulary — redacting a Rule would make
// records unfilterable.
//
// Redaction runs BEFORE Audit.Log, which computes the hash, so the chain commits
// to the redacted text rather than the raw text.
func (g *Gateway) log(e audit.Event) {
	if g.Audit == nil {
		return
	}
	// The sweep itself must be panic-proof. g.log is called from the handler's
	// panic-recovery defer, and the thing that panicked is very often the
	// Redactor — so sweeping audit text with that same Redactor would panic a
	// second time INSIDE the recovery handler. net/http recovers per connection,
	// but a re-panic there aborts the deferred write entirely: the process loses
	// the one audit record whose whole purpose is to say a request was processed
	// and something blew up. Caught in review by
	// TestAuditMasksKeyOnTheRemainingEarlyReturnPaths/panicking_redactor, which
	// re-panicked rather than merely failing an assertion.
	//
	// Degradation is fail-SAFE, not fail-open: if the redactor cannot be trusted
	// to sweep, the free-text fields are DROPPED rather than written raw. Losing
	// a diagnostic string is recoverable from the upstream logs; leaking PII or a
	// reflected credential into a tamper-evident record is not.
	if ok := sweepAuditText(g, &e); !ok {
		// Fail-SAFE, but not fail-STUPID. Free text is dropped rather than written
		// raw — losing a diagnostic string is recoverable from the upstream logs,
		// while leaking PII into a tamper-evident record is not.
		//
		// Meta keys in auditSafeMetaKeys are preserved, because their values are
		// gateway-generated from a CLOSED vocabulary and provably cannot carry
		// request or upstream content. Dropping those too would be over-redaction
		// in the mirror direction: the panic event is the one record proving a
		// request was processed and something blew up, and "what type of value
		// blew up" is the triage signal an operator needs. Caught by
		// TestBL14_PanicValueNeverReachesAuditReason during implementation.
		preserved := map[string]any{}
		for _, k := range auditSafeMetaKeys {
			if v, present := e.Meta[k]; present {
				preserved[k] = v
			}
		}
		e.Model = ""
		e.Reason = ""
		e.Meta = preserved
		setMeta(&e, "audit_redaction", "unavailable")
	}
	// A failed append breaks the hash chain, so it must not be silent. Failing the
	// request would be worse - an audit backend hiccup would take down inference -
	// but the operator has to see it.
	if err := g.Audit.Log(e); err != nil {
		log.Printf("open-ai-gateway: audit append FAILED (chain may be incomplete): %v", err)
	}
}

// streamingRefusalDetail names whichever guarantee actually forced the refusal,
// so the operator is told the true reason instead of being pointed at a config
// knob that may be irrelevant. Naming a knob that is already off sends them in a
// circle; a refusal message that cannot be acted on is its own defect.
func streamingRefusalDetail(g *Gateway) string {
	switch {
	case g.RedactResponse && g.Limiter.HasBudget():
		return "re-send without stream:true, or disable response redaction " +
			`("redact_response": false) and remove the token budget`
	case g.RedactResponse:
		return "re-send the request without stream:true, or set " +
			`"redact_response": false` + " in the gateway config"
	default:
		return "re-send the request without stream:true, or remove the " +
			"cumulative token budget (streamed responses carry no usage figure " +
			"the gateway can account against)"
	}
}

// auditSafeMetaKeys are Meta keys whose values the gateway generates itself from
// a closed vocabulary, so they cannot carry request or upstream content. They
// survive the fail-safe drop in g.log for the case where the Redactor cannot be
// trusted to sweep. Keep this list SHORT and justified per key: every entry is a
// claim that the value is gateway-authored, and a key added here whose value is
// ever derived from outside the gateway becomes a leak that no test will catch.
var auditSafeMetaKeys = []string{"panic_type"}

// sweepAuditText redacts the free-text fields of an audit event in place and
// reports whether it succeeded. It never panics: a redactor that blows up is the
// exact situation in which the audit trail is most needed, so this returns false
// and lets the caller drop the fields instead of crashing the recovery handler.
//
// Returns true when every field was swept cleanly. A false return means the
// event's Model/Reason/Meta could NOT be verified clean and must not be written.
// auditSweepExempt names the audit.Event fields that are DELIBERATELY not swept.
//
// Every other string-bearing field is swept by default. That direction is the whole
// point of this list, and it is why BL-18 was a blocker: the previous version of
// sweepAuditText hardcoded Model, Reason and Meta by name, so it swept exactly the
// three fields its author remembered. audit.Event has eleven. Adding a twelfth —
// say a `Detail string` populated from an upstream error body — would flow straight
// into the tamper-evident log unswept, and nothing would fail: no compile error, no
// test, no runtime signal. That is precisely the rounds-1-to-5 failure mode (an
// enumerated list, one entry behind reality) reappearing inside the commit whose
// message claimed to escape enumeration.
//
// So the sweep is derived by reflection and this list is the EXEMPTION set, not the
// inclusion set. A new field is swept automatically unless someone adds it here and
// justifies it. TestBL18_ExemptFieldListIsStillAccurate fails if an exempt name no
// longer exists on the struct, so the list cannot rot into exempting fields that
// were renamed away while real ones get swept twice.
var auditSweepExempt = map[string]string{
	// Gateway-generated from a CLOSED vocabulary the attacker cannot extend with
	// content. Sweeping Action would turn "allow"/"deny" into "[REDACTED]" and make
	// every record unfilterable, which destroys the trail's entire purpose.
	"Action": "closed vocabulary (allow/deny/rate_limited/...); sweeping it makes records unfilterable",
	// Rule names come from operator configuration, not from the request or the
	// upstream. An operator who names a rule after PII has a configuration problem
	// the gateway cannot solve by mangling its own vocabulary.
	"Rule": "operator-configured rule id; not attacker-controlled",
	// Timestamp, set by the gateway.
	"Time": "gateway-generated timestamp",
	// Already masked by maskKey at every construction site, and sweeping a masked
	// key would destroy the attribution that identifies which caller a record
	// belongs to. Pinned by TestAuditNeverContainsTheRawAPIKey.
	"APIKey": "masked at every construction site by maskKey",
	// Chain-integrity fields. Sweeping them would break hash continuity and the
	// tamper-evidence property itself, and they are gateway-computed hashes rather
	// than text.
	"PrevHash": "chain linkage, gateway-computed",
	"Hash":     "chain integrity, gateway-computed",
	// Redactions is the OUTPUT of the sweep — the kinds it recorded. Sweeping its
	// own accumulator would corrupt the finding list mid-traversal.
	"Redactions": "the sweep's own output accumulator",
	// Tokens is an int64 accounting figure, not text.
	"Tokens": "numeric, cannot carry text",
}

// sweepAuditText redacts every text-bearing field of an audit event before it can
// be written. It is the single chokepoint for audit egress: every path in ServeHTTP
// logs through g.log, and g.log calls this before handing the event to the chain.
//
// The field set is DERIVED BY REFLECTION, not enumerated, so that adding a field to
// audit.Event cannot silently create an unswept egress channel. See
// auditSweepExempt for the deliberately exempt fields and the reasoning per field.
//
// ok is false when the redactor could not be trusted (it panicked), in which case
// g.log drops the free text rather than writing it raw. The recover here is
// load-bearing: g.log is called from the handler's panic-recovery defer, and the
// thing that panicked is very often the Redactor itself, so sweeping with it would
// panic a second time INSIDE the recovery handler and abort the deferred write —
// losing the one audit record whose purpose is to say a request was processed and
// something blew up.
func sweepAuditText(g *Gateway, e *audit.Event) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	c := &sweepCtx{r: g.redactor(), prefix: "audit"}

	// Walk the struct by reflection. Settable string and composite fields are
	// swept; exempt and non-text fields are skipped with their reason recorded in
	// the map above so the decision is reviewable.
	v := reflect.ValueOf(e).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, exempt := auditSweepExempt[name]; exempt {
			continue
		}
		f := v.Field(i)
		if !f.CanSet() {
			// An unexported field cannot be swept and cannot be marshalled either,
			// so it is not an egress channel. Fail closed anyway: if a future field
			// is unexported but somehow serializable, the tripwire test catches it.
			continue
		}
		swept := sweepValue(f.Interface(), c)

		// Assign through reflection ONLY when the swept value is genuinely
		// assignable back to the field. Two ways this can fail, and both must not
		// become a panic:
		//
		//   - sweepValue returns an untyped nil for a nil input, and
		//     reflect.ValueOf(nil) is the INVALID Value; calling Set with it panics.
		//     A nil Meta is the common case (most events carry no Meta), so without
		//     this guard EVERY ordinary event would panic, be recovered, and take
		//     the fail-safe branch — dropping Model and Reason on all of them. That
		//     is a silent, total degradation of the audit trail dressed up as
		//     "working".
		//   - a future field whose type sweepValue does not preserve would not be
		//     assignable either.
		//
		// On either failure the field is DROPPED (zeroed) rather than left holding
		// unswept text, which is the same fail-safe direction g.log uses: losing a
		// diagnostic is recoverable, leaking into a tamper-evident record is not.
		rv := reflect.ValueOf(swept)
		if !rv.IsValid() || !rv.Type().AssignableTo(f.Type()) {
			f.Set(reflect.Zero(f.Type()))
			continue
		}
		f.Set(rv)
	}

	// c.kinds are the finding labels produced during the walk; they are the audit
	// trail's record of WHAT was redacted, and are appended to the exempt
	// Redactions field rather than being swept themselves.
	for _, k := range c.kinds {
		e.Redactions = append(e.Redactions, k)
	}
	return true
}

// panicTypeName names the TYPE of a recovered panic value without ever
// formatting the value itself. A panic value can be any interface{}, including a
// string holding request content, so `%v` on it is both a log-injection and a
// credential-echo channel (BL-14ii). Type names come from a closed vocabulary the
// attacker cannot extend with content.
func panicTypeName(rec any) string {
	switch rec.(type) {
	case nil:
		return "nil"
	case string:
		return "string"
	case error:
		return "error"
	default:
		return fmt.Sprintf("%T", rec)
	}
}

// errNotJSONObject is returned for a body that is valid JSON but not an object
// (e.g. "null"), which would otherwise decode to a nil map and look parseable.
var errNotJSONObject = errors.New("body is not a JSON object")

// decodeJSONObject parses a request body as a JSON object. Anything else
// (array, scalar, malformed JSON) is an error: the gateway must not forward a
// body it cannot inspect.
func decodeJSONObject(body []byte) (map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, errNotJSONObject
	}
	return parsed, nil
}

// stringField reads a string member, returning "" when absent or non-string.
func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// wantsStreaming reports whether the client asked for a streaming response.
//
// It accepts the non-boolean truthy forms clients actually emit - "stream":
// "true" as a string, "stream": 1 as a number - not just a JSON boolean. A
// bool-only check was bypassable by those two forms: the request went upstream as
// a streaming call, the gateway could not redact the SSE it got back, and the
// refusal that existed to prevent exactly that never fired. (The response-side
// non-JSON 2xx guard still caught it, so nothing leaked, but the client received
// a misleading error and the request had already transited upstream.)
func wantsStreaming(m map[string]any) bool {
	switch v := m["stream"].(type) {
	case bool:
		return v
	case string:
		// Match the truthy spellings used by OpenAI-compatible SDKs and shell
		// templates that interpolate the value as a string.
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
		return false
	case float64:
		return v != 0
	case json.Number:
		n, err := v.Int64()
		return err == nil && n != 0
	default:
		return false
	}
}

// messagesShapeInspectable reports whether the request's "messages" member is in a
// shape this gateway can inspect.
//
// This exists because "key absent" and "key present but unreadable" must NOT be
// treated the same way:
//
//   - absent (or explicitly null) -> true. An embeddings-style or completions
//     body legitimately carries no messages, and there is nothing to inspect.
//   - present as an array          -> true. Each element is then classified by
//     extractContent, which fails closed on anything it cannot read.
//   - present as ANY other shape   -> false. An object, a string, a number or a
//     bool here means model input the gateway cannot read, so it must be refused
//     rather than forwarded.
//
// The third case was a live bypass: {"messages":{"role":"user","content":"my
// email is jane.doe@example.com"}} forwarded VERBATIM upstream with status 200.
// extractContent failed its []any type assertion on the container and reported
// "no content" instead of "content I could not read", and the handler's guard was
// additionally gated on hasMessages, which failed the same assertion - so the
// guard could never fire for precisely the shape that needed it. Policy matched
// nothing and redaction rewrote nothing, while the request still went out. That is
// the same bypass-by-shape class the content-shape work closed, one level up.
//
// hasMessages is gone for that reason: a second, differently-failing shape check
// on the same field is how the guard became unreachable. extractContent returning
// ok=false is now the single source of truth for "input I could not inspect".
func messagesShapeInspectable(m map[string]any) bool {
	v, present := m["messages"]
	if !present {
		return true
	}
	switch v.(type) {
	case nil:
		// "messages": null carries no input.
		return true
	case []any:
		// Per-element shapes are classified by extractContent.
		return true
	default:
		return false
	}
}

// extractContent flattens every message's TEXT into one string for policy
// matching and redaction, and reports whether every shape it saw was understood.
//
// It handles the three content shapes OpenAI-compatible clients actually send:
//   - "content": "text"                              (plain string)
//   - "content": [{"type":"text","text":"..."}, ...] (multimodal parts)
//   - "content": null                                (tool-call turns)
//
// Returning ok=false for an unrecognised shape is load-bearing: the caller fails
// closed rather than forwarding content that policy and redaction never saw.
// The previous implementation typed content as a plain string and discarded the
// unmarshal error, so multimodal requests produced EMPTY content and silently
// bypassed both.
func extractContent(m map[string]any) (string, bool) {
	// A "messages" member that is present but not an array is content the gateway
	// cannot read, not absent content - see messagesShapeInspectable. Report it as
	// unclassified so the caller fails closed.
	if !messagesShapeInspectable(m) {
		return "", false
	}
	msgs, ok := m["messages"].([]any)
	if !ok {
		// No messages array (absent or null): nothing textual to inspect. Not an
		// error - this can be an embeddings-style body.
		return "", true
	}
	parts := make([]string, 0, len(msgs))
	for _, raw := range msgs {
		msg, ok := raw.(map[string]any)
		if !ok {
			return "", false
		}
		switch c := msg["content"].(type) {
		case nil:
			// Tool-call / assistant turns legitimately carry no content.
			continue
		case string:
			parts = append(parts, c)
		case []any:
			// Multimodal parts: inspect every text part. Image and other
			// non-text parts are skipped, but their presence is not an error.
			for _, pt := range c {
				part, ok := pt.(map[string]any)
				if !ok {
					return "", false
				}
				if v, present := part["text"]; present {
					s, ok := v.(string)
					if !ok {
						return "", false
					}
					parts = append(parts, s)
				}
			}
		default:
			// Number, bool, object: content we cannot read as text.
			return "", false
		}
	}
	return strings.Join(parts, "\n"), true
}

// redactRequestContent redacts sensitive text throughout the request's messages
// IN PLACE, preserving every other field and the original content shape.
//
// It rewrites string content, and each {type:text,text:...} part of a multimodal
// content array (image and other non-text parts are left untouched).
//
// It returns:
//   - (body, kinds, nil) when something was redacted and the body re-marshalled
//   - (nil, nil, nil)    when nothing sensitive was found (no rewrite needed)
//   - (nil, kinds, err)  when sensitive content WAS found but the body could not
//     be re-marshalled
//
// That third case is why this returns an error rather than a bool: collapsing it
// into ok=false made the caller keep the ORIGINAL bytes, forwarding raw PII
// upstream while the audit trail still recorded a redaction. The caller fails
// closed on it. Unrecognised content shapes never reach here - extractContent has
// already failed closed on them.
// redactRequestContent redacts a client request body before it is forwarded
// upstream, in place, preserving every field the client sent.
//
// BL-11: this used to be an ENUMERATED walker - messages[].content strings and
// parts[].text only - which is precisely the design four review rounds proved
// insufficient on the response side. The response half was converted to a total
// sweep and this half was not, so PII in metadata.user_email, prompt,
// tools[].function.description, the top-level user field, or an image_url data URI
// was forwarded to the provider verbatim. That leaks in the direction
// RedactRequest exists to close (client -> upstream), and it also let a ContentRe
// deny rule be bypassed by field choice.
//
// It now runs the same sweepValue traversal as the response path, so the two
// directions cannot drift apart, and object keys are swept too. Non-string fields
// are untouched, which is what keeps the request semantically intact: model,
// stream, temperature, max_tokens, top_p, stop, n, tools, tool_choice and
// response_format all survive, because the redactor only rewrites strings that
// match a PII pattern.
//
// The (nil, nil, nil) return means "nothing sensitive found" and is deliberately
// distinct from an error: collapsing the two is how the original bug forwarded raw
// PII under an audit line claiming it had been redacted.
func redactRequestContent(parsed map[string]any, r redactor.Redactor) ([]byte, []string, error) {
	c := &sweepCtx{r: r, prefix: "req"}
	sweepValue(parsed, c)
	if len(c.kinds) == 0 {
		return nil, nil, nil
	}
	out, err := marshalMap(parsed)
	if err != nil {
		return nil, c.kinds, err
	}
	return out, c.kinds, nil
}

func extractKey(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	auth := r.Header.Get("Authorization")
	return strings.TrimPrefix(auth, "Bearer ")
}

func maskKey(k string) string {
	if len(k) <= 4 {
		return "****"
	}
	return k[:4] + "…"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
