package main

import (
	"os"
	"path/filepath"
	"testing"
)

// AP-1: the Shodan API key must come from the environment only — argv is
// visible in ps output and shell history, so no -shodan-key flag may exist.

func TestNewShodanSourceMockNeedsNoKey(t *testing.T) {
	src, err := newShodanSource("mock", "")
	if err != nil {
		t.Fatalf("mock source with empty key: %v", err)
	}
	if src.Name() != "mock" {
		t.Fatalf("expected mock source, got %q", src.Name())
	}
}

func TestNewShodanSourceRequiresEnvKey(t *testing.T) {
	if _, err := newShodanSource("shodan", ""); err == nil {
		t.Fatal("expected error for live source with empty key")
	}
}

func TestShodanKeyFromEnv(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "env-only-key")
	if got := shodanKeyFromEnv(); got != "env-only-key" {
		t.Fatalf("shodanKeyFromEnv() = %q, want env value", got)
	}
	os.Unsetenv("SHODAN_API_KEY")
	if got := shodanKeyFromEnv(); got != "" {
		t.Fatalf("shodanKeyFromEnv() = %q, want empty", got)
	}
	_ = filepath.Join // silence unused import if helpers change
}

func TestHelpTextHasNoArgvKeyFlag(t *testing.T) {
	// The flag set must not register a -shodan-key flag anymore.
	fs, _ := newFlagSet()
	if fs.Lookup("shodan-key") != nil {
		t.Fatal("-shodan-key flag still registered: credentials must never be on argv (AP-1)")
	}
	for _, name := range []string{"scenario", "format", "shodan", "shodan-source"} {
		if fs.Lookup(name) == nil {
			t.Fatalf("expected flag -%s to still be registered", name)
		}
	}
}
