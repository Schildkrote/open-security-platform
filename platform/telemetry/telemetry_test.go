package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoopDoesNotPanic(t *testing.T) {
	var m Meter = Noop{}
	m.Count("x", 1, nil)
	end := m.Span("s", nil)
	end()
}

func TestInMemoryRecords(t *testing.T) {
	m := &InMemory{}
	m.Count("requests", 3, map[string]string{"route": "/x"})
	end := m.Span("op", nil)
	end()
	if len(m.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(m.Records))
	}
	if m.Records[0].Kind != "counter" || m.Records[0].Value != 3 {
		t.Errorf("unexpected counter record: %+v", m.Records[0])
	}
	if m.Records[1].Kind != "span" {
		t.Errorf("unexpected span record: %+v", m.Records[1])
	}
}

func TestOTLPExports(t *testing.T) {
	var got []Record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var rec Record
		_ = json.Unmarshal(b, &rec)
		got = append(got, rec)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewOTLP(srv.URL)
	m.Count("events", 5, map[string]string{"src": "test"})
	if len(got) != 1 || got[0].Name != "events" || got[0].Value != 5 {
		t.Fatalf("expected exported counter, got %+v", got)
	}
}
