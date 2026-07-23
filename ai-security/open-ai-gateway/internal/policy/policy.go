// Package policy implements the gateway's request policy engine.
package policy

import "regexp"

// Action is what the engine decides to do with a request.
type Action string

const (
	Allow  Action = "allow"
	Deny   Action = "deny"
	Redact Action = "redact"
)

// Rule is a single policy statement. A rule matches when every non-empty
// matcher matches. Rules are evaluated in order; the first match wins.
type Rule struct {
	Name         string   `json:"name"`
	ModelPattern string   `json:"model_pattern,omitempty"` // regex against requested model
	ContentRe    string   `json:"content_re,omitempty"`    // regex against flattened content
	APIKeys      []string `json:"api_keys,omitempty"`      // restrict to these caller keys
	Action       Action   `json:"action"`
	Reason       string   `json:"reason,omitempty"`

	modelRe   *regexp.Regexp
	contentRe *regexp.Regexp
}

// Engine holds an ordered rule set and a default action.
type Engine struct {
	Default Action
	Rules   []Rule
}

// Compile prepares regexes. Call once after loading config.
func (e *Engine) Compile() error {
	for i := range e.Rules {
		r := &e.Rules[i]
		if r.ModelPattern != "" {
			re, err := regexp.Compile(r.ModelPattern)
			if err != nil {
				return err
			}
			r.modelRe = re
		}
		if r.ContentRe != "" {
			re, err := regexp.Compile(r.ContentRe)
			if err != nil {
				return err
			}
			r.contentRe = re
		}
	}
	return nil
}

// Request is the normalized view of an inbound call the engine evaluates.
type Request struct {
	Model   string
	Content string
	APIKey  string
}

// Decision is the outcome of evaluation.
type Decision struct {
	Action Action
	Rule   string
	Reason string
}

// Evaluate returns the decision for a request.
func (e *Engine) Evaluate(req Request) Decision {
	for _, r := range e.Rules {
		if r.modelRe != nil && !r.modelRe.MatchString(req.Model) {
			continue
		}
		if r.contentRe != nil && !r.contentRe.MatchString(req.Content) {
			continue
		}
		if len(r.APIKeys) > 0 && !contains(r.APIKeys, req.APIKey) {
			continue
		}
		return Decision{Action: r.Action, Rule: r.Name, Reason: r.Reason}
	}
	return Decision{Action: e.Default}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
