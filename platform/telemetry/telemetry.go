// Package telemetry provides shared observability scaffolding (Phase 4): a
// minimal metrics/span sink with a no-op offline default, an in-memory sink for
// tests, and an OpenTelemetry (OTLP/HTTP) exporter for production. It is
// intentionally tiny and stdlib-only, so components can emit counters/spans
// without taking an OTel SDK dependency.
package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Meter records counters and spans.
type Meter interface {
	Count(name string, value int64, attrs map[string]string)
	Span(name string, attrs map[string]string) func() // returns an end function
}

// Noop is the offline default (discards everything).
type Noop struct{}

// Count implements Meter.
func (Noop) Count(string, int64, map[string]string) {}

// Span implements Meter.
func (Noop) Span(string, map[string]string) func() { return func() {} }

// Record is a single metric/span observation.
type Record struct {
	Name  string            `json:"name"`
	Kind  string            `json:"kind"` // "counter" | "span"
	Value int64             `json:"value,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
	Time  time.Time         `json:"time"`
}

// InMemory collects records (for tests / debugging).
type InMemory struct {
	mu      sync.Mutex
	Records []Record
}

// Count implements Meter.
func (m *InMemory) Count(name string, value int64, attrs map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Records = append(m.Records, Record{Name: name, Kind: "counter", Value: value, Attrs: attrs, Time: time.Now()})
}

// Span implements Meter.
func (m *InMemory) Span(name string, attrs map[string]string) func() {
	start := time.Now()
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.Records = append(m.Records, Record{
			Name: name, Kind: "span", Value: time.Since(start).Microseconds(), Attrs: attrs, Time: start,
		})
	}
}

// OTLP exports records to an OTLP/HTTP endpoint (best-effort).
type OTLP struct {
	Endpoint string
	client   *http.Client
}

// NewOTLP targets an OTLP/HTTP endpoint (e.g. http://collector:4318/v1/metrics).
func NewOTLP(endpoint string) *OTLP {
	return &OTLP{Endpoint: endpoint, client: &http.Client{Timeout: 5 * time.Second}}
}

// Count implements Meter.
func (o *OTLP) Count(name string, value int64, attrs map[string]string) {
	o.send(Record{Name: name, Kind: "counter", Value: value, Attrs: attrs, Time: time.Now()})
}

// Span implements Meter.
func (o *OTLP) Span(name string, attrs map[string]string) func() {
	start := time.Now()
	return func() {
		o.send(Record{
			Name: name, Kind: "span", Value: time.Since(start).Microseconds(), Attrs: attrs, Time: start,
		})
	}
}

func (o *OTLP) send(rec Record) {
	body, err := json.Marshal(rec)
	if err != nil {
		return
	}
	resp, err := o.client.Post(o.Endpoint, "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}
