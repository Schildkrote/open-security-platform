// Package probe implements the four live-gated recon features:
//
//   - active scanning (port/service probes + HTTP requests)
//   - account-recovery / account-existence probing
//   - people-search / background-check aggregation
//   - authenticated platform scraping / contact harvesting
//
// Every feature ships a mock implementation (offline, deterministic) and a
// real implementation (network I/O). The real path is only reached when the
// caller has enabled the corresponding live-gate feature; the mock path is
// the default and what CI exercises.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Feature identifiers mirror the livegate constants (kept local so the
// component stays self-contained; the CLI validates against livegate).
const (
	FeatureActiveScanning      = "active-scanning"
	FeatureRecoveryProbing     = "recovery-probing"
	FeaturePeopleSearch        = "people-search"
	FeatureAuthenticatedScrape = "authenticated-scrape"
)

// ProbeResult is the outcome of one live probe.
type ProbeResult struct {
	Feature   string         `json:"feature"`
	Target    string         `json:"target"`
	Found     bool           `json:"found"`
	Uncertain bool           `json:"uncertain"`
	Detail    string         `json:"detail"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	LatencyMS int64          `json:"latency_ms"`
}

// Runner executes one feature against a target.
type Runner interface {
	Name() string
	Feature() string
	Run(ctx context.Context, target string, opts RunOpts) (*ProbeResult, error)
}

// RunOpts carries the per-invocation scope + credentials for a live run.
type RunOpts struct {
	// Consent is required for people-search (subject consent flag).
	Consent bool
	// Credential is the user-supplied session for authenticated scraping
	// (memory/env only; never argv, never the audit log).
	Credential string
	// RateLimitMS is the per-target delay between probes (0 = none).
	RateLimitMS int
}

// --- active scanning ------------------------------------------------------

// ActiveScanner probes a host:port list with TCP connect + optional HTTP
// GET. Read-only; no auth, no exploit, no DoS.
type ActiveScanner struct {
	Client  *http.Client
	Timeout time.Duration
}

func NewActiveScanner() *ActiveScanner {
	return &ActiveScanner{Client: &http.Client{}, Timeout: 3 * time.Second}
}

func (a *ActiveScanner) Name() string    { return "active-scanner" }
func (a *ActiveScanner) Feature() string { return FeatureActiveScanning }

// Run probes a single "host:port" target (TCP connect). If the port serves
// HTTP (80/8080/443 or the probe is told to), it also issues one GET.
func (a *ActiveScanner) Run(ctx context.Context, target string, _ RunOpts) (*ProbeResult, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("target %q must be host:port", target)
	}
	if a.Timeout <= 0 {
		a.Timeout = 3 * time.Second
	}
	if a.Client == nil {
		a.Client = &http.Client{}
	}
	start := time.Now()
	d := net.Dialer{Timeout: a.Timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	res := &ProbeResult{Feature: a.Feature(), Target: target, LatencyMS: time.Since(start).Milliseconds()}
	if err != nil {
		res.Detail = "tcp closed: " + err.Error()
		return res, nil
	}
	conn.Close()
	res.Found = true
	res.Detail = "tcp open"
	res.Evidence = map[string]any{"host": host, "port": portStr}

	// HTTP GET on well-known web ports (read-only).
	switch portStr {
	case "80", "8080", "443":
		scheme := "http"
		if portStr == "443" {
			scheme = "https"
		}
		hctx, cancel := context.WithTimeout(ctx, a.Timeout)
		defer cancel()
		req, _ := http.NewRequestWithContext(hctx, http.MethodGet, scheme+"://"+host+":"+portStr+"/", nil)
		req.Header.Set("User-Agent", "live-recon/0.1 (+https://github.com/Schildkrote/open-security-platform)")
		resp, gerr := a.Client.Do(req)
		if gerr == nil {
			defer resp.Body.Close()
			res.Evidence["http_status"] = resp.StatusCode
			res.Detail = "tcp open; http " + itoa(resp.StatusCode)
		}
	}
	return res, nil
}

// --- recovery probing -----------------------------------------------------

// RecoveryProber queries a password-reset / account-existence endpoint for
// differential responses. At most one state-changing request per identifier
// (enforced by the caller's cap; the prober itself is idempotent per run).
type RecoveryProber struct {
	Client  *http.Client
	Timeout time.Duration
}

func NewRecoveryProber() *RecoveryProber {
	return &RecoveryProber{Client: &http.Client{}, Timeout: 5 * time.Second}
}

func (r *RecoveryProber) Name() string    { return "recovery-prober" }
func (r *RecoveryProber) Feature() string { return FeatureRecoveryProbing }

// Run probes the reset endpoint for one identifier. target is the reset URL
// template with {identifier}; opts.Credential carries the identifier value
// (reused so the interface is uniform).
func (r *RecoveryProber) Run(ctx context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	credential := opts.Credential
	if r.Timeout <= 0 {
		r.Timeout = 5 * time.Second
	}
	if r.Client == nil {
		r.Client = &http.Client{}
	}
	urlOut := strings.ReplaceAll(target, "{identifier}", credential)
	start := time.Now()
	hctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, urlOut, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "live-recon/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	resp, err := r.Client.Do(req)
	if err != nil {
		return &ProbeResult{Feature: r.Feature(), Target: target, Uncertain: true,
			Detail: err.Error(), LatencyMS: time.Since(start).Milliseconds()}, nil
	}
	defer resp.Body.Close()
	res := &ProbeResult{
		Feature: r.Feature(), Target: target,
		Detail:    fmt.Sprintf("http %d (differential)", resp.StatusCode),
		LatencyMS: time.Since(start).Milliseconds(),
		Evidence:  map[string]any{"http_status": resp.StatusCode},
	}
	// 200 with a "no account" body vs 200 with a "check your email" body is
	// the usual differential; we report the status and let the caller
	// classify. 404 → uncertain (site hides existence).
	if resp.StatusCode == http.StatusOK {
		res.Found = true
	} else if resp.StatusCode >= 400 {
		res.Uncertain = true
	}
	return res, nil
}

// --- people search --------------------------------------------------------

// PeopleSearcher queries a source whitelist for one subject. Read-only GETs;
// subject consent is required (opts.Consent). Results are redacted: the
// subject's name is carried only in the Target field, never in Evidence.
type PeopleSearcher struct {
	Client    *http.Client
	Timeout   time.Duration
	Whitelist []string // allowed source hosts
}

func NewPeopleSearcher() *PeopleSearcher {
	return &PeopleSearcher{
		Client:    &http.Client{},
		Timeout:   5 * time.Second,
		Whitelist: []string{"www.spokeo.com", "fastpeoplesearch.com", "truepeoplesearch.com"},
	}
}

func (p *PeopleSearcher) Name() string    { return "people-searcher" }
func (p *PeopleSearcher) Feature() string { return FeaturePeopleSearch }

// Run queries the first whitelisted source for the subject (opts.Credential
// carries the query term, e.g. name or email).
func (p *PeopleSearcher) Run(ctx context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	if !opts.Consent {
		return nil, fmt.Errorf("people-search requires subject consent (--consent)")
	}
	if p.Timeout <= 0 {
		p.Timeout = 5 * time.Second
	}
	if p.Client == nil {
		p.Client = &http.Client{}
	}
	start := time.Now()
	res := &ProbeResult{Feature: p.Feature(), Target: target}
	for _, host := range p.Whitelist {
		u := "https://" + host + "/search?q=" + opts.Credential
		hctx, cancel := context.WithTimeout(ctx, p.Timeout)
		req, err := http.NewRequestWithContext(hctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "live-recon/0.1 (+https://github.com/Schildkrote/open-security-platform)")
		resp, err := p.Client.Do(req)
		cancel()
		if err != nil {
			res.Uncertain = true
			res.Detail = err.Error()
			break
		}
		res.Found = resp.StatusCode < 400
		res.Detail = fmt.Sprintf("%s: http %d", host, resp.StatusCode)
		res.Evidence = map[string]any{"source": host, "http_status": resp.StatusCode}
		resp.Body.Close()
		break // one query per source per run (data minimization)
	}
	res.LatencyMS = time.Since(start).Milliseconds()
	return res, nil
}

// --- authenticated scraping -----------------------------------------------

// AuthScraper harvests contacts from a platform using a user-supplied
// session. Read-only; the credential is used only in the request header and
// is never written to Evidence.
type AuthScraper struct {
	Client  *http.Client
	Timeout time.Duration
}

func NewAuthScraper() *AuthScraper {
	return &AuthScraper{Client: &http.Client{}, Timeout: 5 * time.Second}
}

func (s *AuthScraper) Name() string    { return "auth-scraper" }
func (s *AuthScraper) Feature() string { return FeatureAuthenticatedScrape }

// Run issues one authenticated read-only GET against target. The credential
// is sent as a Bearer token. Evidence carries only non-PII response metadata.
func (s *AuthScraper) Run(ctx context.Context, target string, opts RunOpts) (*ProbeResult, error) {
	if opts.Credential == "" {
		return nil, fmt.Errorf("authenticated-scrape requires a credential (env var)")
	}
	if s.Timeout <= 0 {
		s.Timeout = 5 * time.Second
	}
	if s.Client == nil {
		s.Client = &http.Client{}
	}
	start := time.Now()
	hctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Credential)
	req.Header.Set("User-Agent", "live-recon/0.1 (+https://github.com/Schildkrote/open-security-platform)")
	resp, err := s.Client.Do(req)
	if err != nil {
		return &ProbeResult{Feature: s.Feature(), Target: target, Uncertain: true,
			Detail: err.Error(), LatencyMS: time.Since(start).Milliseconds()}, nil
	}
	defer resp.Body.Close()
	res := &ProbeResult{
		Feature: s.Feature(), Target: target,
		Found:     resp.StatusCode < 400,
		Detail:    fmt.Sprintf("http %d (auth)", resp.StatusCode),
		LatencyMS: time.Since(start).Milliseconds(),
		Evidence:  map[string]any{"http_status": resp.StatusCode},
	}
	return res, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
