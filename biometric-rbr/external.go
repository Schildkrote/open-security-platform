// Copyright 2026 open-biometric-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package rbr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// ExternalEmbedder loads precomputed embeddings from a directory or JSON
// table produced by the Python train.embedder pipeline (or InsightFace).
//
// Layout options:
//  1. JSON file: {"image_hash": [f32, ...], ...}
//  2. Directory of <image_hash>.f32 little-endian float32 blobs
//
// This keeps the Go binary free of ONNX runtime deps while still consuming
// real ArcFace/SFace vectors computed offline.
type ExternalEmbedder struct {
	table map[string]Embedding
	dim   int
	label string
}

// NewExternalEmbedder loads from a JSON table path or a directory of .f32 files.
func NewExternalEmbedder(path string) (*ExternalEmbedder, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("external embedder path: %w", err)
	}
	e := &ExternalEmbedder{table: map[string]Embedding{}, label: "external"}
	if st.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			if filepath.Ext(name) != ".f32" {
				continue
			}
			hash := name[:len(name)-len(".f32")]
			raw, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				return nil, err
			}
			if len(raw)%4 != 0 {
				return nil, fmt.Errorf("%s: length not multiple of 4", name)
			}
			n := len(raw) / 4
			vec := make(Embedding, n)
			for i := 0; i < n; i++ {
				bits := binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
				vec[i] = float64(math.Float32frombits(bits))
			}
			e.table[hash] = l2normalize([]float64(vec))
			if e.dim == 0 {
				e.dim = n
			}
		}
		if len(e.table) == 0 {
			return nil, fmt.Errorf("no .f32 files in %s", path)
		}
		return e, nil
	}
	// JSON table
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string][]float64
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse embedding table: %w", err)
	}
	for k, v := range raw {
		if e.dim == 0 {
			e.dim = len(v)
		}
		if len(v) != e.dim {
			return nil, fmt.Errorf("dim mismatch for %s: %d != %d", k, len(v), e.dim)
		}
		e.table[k] = l2normalize(append([]float64(nil), v...))
	}
	if len(e.table) == 0 {
		return nil, fmt.Errorf("empty embedding table %s", path)
	}
	return e, nil
}

func (e *ExternalEmbedder) Name() string { return e.label }

// Embed looks up imageHash in the precomputed table.
func (e *ExternalEmbedder) Embed(imageHash string) (Embedding, error) {
	v, ok := e.table[imageHash]
	if !ok {
		return nil, fmt.Errorf("external embedder: no vector for %q", imageHash)
	}
	out := make(Embedding, len(v))
	copy(out, v)
	return out, nil
}

// Dim returns the embedding dimensionality.
func (e *ExternalEmbedder) Dim() int { return e.dim }

// NewEmbedder selects mock or external based on path ("" → mock).
func NewEmbedder(externalPath string) (Embedder, error) {
	if externalPath == "" {
		return NewMockEmbedder(), nil
	}
	return NewExternalEmbedder(externalPath)
}
