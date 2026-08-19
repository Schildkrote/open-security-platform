// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package rbr

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalJSONTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emb.json")
	// Two orthogonal unit-ish vectors
	content := `{"alice-1":[1,0,0,0],"bob-1":[0,1,0,0]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := NewExternalEmbedder(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.Embed("alice-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.Embed("bob-1")
	if Cosine(a, a) < 0.999 {
		t.Fatalf("self cos=%f", Cosine(a, a))
	}
	if Cosine(a, b) > 0.01 {
		t.Fatalf("orthogonal cos=%f", Cosine(a, b))
	}
	if _, err := e.Embed("missing"); err == nil {
		t.Fatal("want miss error")
	}
}

func TestExternalF32Dir(t *testing.T) {
	dir := t.TempDir()
	vec := []float32{0, 0, 1, 0}
	raw := make([]byte, 16)
	for i, v := range vec {
		binary.LittleEndian.PutUint32(raw[i*4:], math.Float32bits(v))
	}
	if err := os.WriteFile(filepath.Join(dir, "x.f32"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := NewExternalEmbedder(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.Embed("x")
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(v[2]-1) > 1e-5 {
		t.Fatalf("vec=%v", v)
	}
}

func TestNewEmbedderFactory(t *testing.T) {
	m, err := NewEmbedder("")
	if err != nil || m.Name() != "mock" {
		t.Fatalf("mock: %v %v", m, err)
	}
}

func TestGalleryWithExternal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emb.json")
	_ = os.WriteFile(path, []byte(`{"h1":[1,0],"h2":[1,0],"other":[0,1]}`), 0o644)
	e, err := NewExternalEmbedder(path)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGallery(e)
	if err := g.Enrol(FaceRecord{ID: "g1", ClientID: "alice", ImageHash: "h1"}, permittedD()); err != nil {
		t.Fatal(err)
	}
	res := g.MatchProbe(FaceRecord{ID: "p", ImageHash: "h2"}, 0.9, true, "general")
	if res.Refused || len(res.Matches) != 1 {
		t.Fatalf("want match: %+v", res)
	}
}
