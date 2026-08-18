// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Schildkrote/username-enum/internal/service"
	"github.com/Schildkrote/username-enum/internal/source"
)

// stub is a deterministic test source: everything containing "hit" is found.
type stub struct {
	calls int
}

func (s *stub) Name() string { return "stub" }
func (s *stub) Probe(_ context.Context, svc, url, username string) (source.Result, error) {
	s.calls++
	return source.Result{Service: svc, URL: url, Found: username == "hit", Uncertain: false, LatencyMS: 1}, nil
}

func testCatalog() service.Catalog {
	return service.Catalog{
		{Name: "a", URL: "https://a.example/{username}", Diff: true, Weight: 3},
		{Name: "b", URL: "https://b.example/{username}", Diff: true, Weight: 2},
	}
}

func TestRunFindsHits(t *testing.T) {
	src := &stub{}
	res, err := Run(context.Background(), testCatalog(), src, "hit", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Found != 2 || res.Total != 2 {
		t.Fatalf("want 2/2 found, got %d/%d", res.Found, res.Total)
	}
	if len(res.ByWeight[3]) != 1 || len(res.ByWeight[2]) != 1 {
		t.Fatalf("by-weight buckets wrong: %+v", res.ByWeight)
	}
}

func TestRunEmptyUsername(t *testing.T) {
	_, err := Run(context.Background(), testCatalog(), &stub{}, "", Options{})
	if !errors.Is(err, errEmptyUsername) {
		t.Fatalf("want errEmptyUsername, got %v", err)
	}
}

func TestRunMaxProbes(t *testing.T) {
	src := &stub{}
	res, err := Run(context.Background(), testCatalog(), src, "hit", Options{MaxProbes: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("want 1 probe, got %d", res.Total)
	}
	if src.calls != 1 {
		t.Fatalf("source called %d times, want 1", src.calls)
	}
}

func TestRunContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, testCatalog(), &stub{}, "hit", Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if res == nil {
		t.Fatal("Run should return partial result on cancel")
	}
}

func TestRunOnProbeHook(t *testing.T) {
	var seen int
	_, err := Run(context.Background(), testCatalog(), &stub{}, "x", Options{
		OnProbe: func(source.Result) { seen++ },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seen != 2 {
		t.Fatalf("OnProbe called %d times, want 2", seen)
	}
}

func TestRunIntervalThrottling(t *testing.T) {
	src := &stub{}
	start := time.Now()
	_, err := Run(context.Background(), testCatalog(), src, "x", Options{Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if time.Since(start) < 30*time.Millisecond {
		t.Fatal("interval throttling not applied")
	}
}
