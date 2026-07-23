// Package registry tracks approved tools and MCP servers and their risk.
package registry

import (
	"sort"
	"sync"
	"time"
)

type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Tool is a registered capability an agent/model may invoke.
type Tool struct {
	Name        string    `json:"name"`
	Kind        string    `json:"kind"` // "mcp" | "function" | "http"
	Endpoint    string    `json:"endpoint,omitempty"`
	Risk        Risk      `json:"risk"`
	Allowed     bool      `json:"allowed"`
	Description string    `json:"description,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	Registered  time.Time `json:"registered"`
}

// Registry is a concurrency-safe in-memory tool/MCP registry.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func New() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.Registered.IsZero() {
		t.Registered = time.Now().UTC()
	}
	r.tools[t.Name] = t
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// IsAllowed reports whether a tool exists and is permitted for use.
func (r *Registry) IsAllowed(name string) bool {
	t, ok := r.Get(name)
	return ok && t.Allowed
}

func (r *Registry) SetAllowed(name string, allowed bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	if !ok {
		return false
	}
	t.Allowed = allowed
	r.tools[name] = t
	return true
}

// List returns tools sorted by name for stable output.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
