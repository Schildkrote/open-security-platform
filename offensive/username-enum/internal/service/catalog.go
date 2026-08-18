// Package service holds the username-enum service catalog: which services
// are probed, by what URL pattern, and how "found" vs "not found" is told
// apart. The catalog follows the public sherlock convention of URL
// templates with a {username} placeholder.
package service

import (
	"fmt"
	"strings"
)

// Service describes one probed platform.
type Service struct {
	Name   string `json:"name"`
	URL    string `json:"url"`    // URL template with {username}
	Diff   bool   `json:"diff"`   // whether the source can tell found vs not-found
	Weight int    `json:"weight"` // 1..3 confidence weight (3 = definitive)
}

// Catalog is the ordered set of services.
type Catalog []Service

// BuiltIn returns the default catalog. The placeholder {username} is
// replaced by the probed username. Services are conservative (only ones with
// a stable public URL pattern and no aggressive rate limiting on GETs).
func BuiltIn() Catalog {
	return Catalog{
		{Name: "github", URL: "https://github.com/{username}", Diff: true, Weight: 3},
		{Name: "gitlab", URL: "https://gitlab.com/{username}", Diff: true, Weight: 3},
		{Name: "mastodon-social", URL: "https://mastodon.social/@{username}", Diff: true, Weight: 2},
		{Name: "reddit", URL: "https://www.reddit.com/user/{username}", Diff: true, Weight: 2},
		{Name: "discord", URL: "https://discord.com/api/v10/users/@me", Diff: false, Weight: 1},
		{Name: "stackexchange", URL: "https://stackexchange.com/users/{username}", Diff: false, Weight: 1},
	}
}

// Lookup returns the service with the given name, or nil.
func (c Catalog) Lookup(name string) *Service {
	for i := range c {
		if c[i].Name == name {
			return &c[i]
		}
	}
	return nil
}

// Filter keeps only services whose names are in keep (case-insensitive).
// An empty keep keeps everything.
func (c Catalog) Filter(keep []string) Catalog {
	if len(keep) == 0 {
		return c
	}
	allowed := map[string]bool{}
	for _, k := range keep {
		allowed[strings.ToLower(k)] = true
	}
	var out Catalog
	for _, s := range c {
		if allowed[strings.ToLower(s.Name)] {
			out = append(out, s)
		}
	}
	return out
}

// BuildURL returns the probed URL for a username, validating that no
// unexpected {username} placeholder remains after substitution.
func BuildURL(tmpl, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("empty username")
	}
	out := strings.ReplaceAll(tmpl, "{username}", username)
	if strings.Contains(out, "{") {
		return "", fmt.Errorf("service URL %q still has placeholders after substitution", out)
	}
	return out, nil
}
