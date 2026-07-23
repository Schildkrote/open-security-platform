package bao

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockStore(t *testing.T) {
	m := NewMock()
	if err := m.Put("cred-1", "s3cr3t"); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := m.Get("cred-1")
	if err != nil || got != "s3cr3t" {
		t.Fatalf("get = %q, %v; want s3cr3t", got, err)
	}
	m.Delete("cred-1")
	if _, err := m.Get("cred-1"); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestClientPut(t *testing.T) {
	var gotMethod, gotPath, gotToken, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok-123")
	if err := c.Put("cred-1", "s3cr3t"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/secret/data/cred-1" {
		t.Errorf("request = %s %s, want POST /v1/secret/data/cred-1", gotMethod, gotPath)
	}
	if gotToken != "tok-123" {
		t.Errorf("X-Vault-Token = %q, want tok-123", gotToken)
	}
	var body struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(gotBody), &body)
	if body.Data.Value != "s3cr3t" {
		t.Errorf("body data.value = %q, want s3cr3t", body.Data.Value)
	}
}

func TestClientGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"hunter2"}}}`))
	}))
	defer srv.Close()

	got, err := NewClient(srv.URL, "tok").Get("cred-1")
	if err != nil || got != "hunter2" {
		t.Fatalf("get = %q, %v; want hunter2", got, err)
	}
}

func TestClientGetMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL, "tok").Get("nope"); err == nil {
		t.Fatal("expected error for missing secret")
	}
}
