// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package passive adds a -domain flag to the attack-path CLI: it resolves a
// domain to a passive Report (offline static table by default) and appends
// the result's exposed hosts as exposure nodes.
package passive

import (
	"github.com/Schildkrote/attack-path/internal/graph"
)

// AddDomainExposures resolves domain via src and appends the result's A/AAAA
// records and the domain itself as exposure nodes. Node IDs are stable:
// "domain:{host}". Existing nodes are left untouched.
func AddDomainExposures(g *graph.Graph, src Source, domain string) (int, error) {
	r, err := src.Resolve(domain)
	if err != nil {
		return 0, err
	}
	n := 0
	add := func(id, name, ip string) {
		if g.HasNode(id) {
			return
		}
		nd := graph.Node{
			ID:       id,
			Type:     graph.TypeExposure,
			Name:     name,
			Exposure: true,
			Props:    map[string]string{"domain": r.Domain, "source": "passive"},
		}
		if ip != "" {
			nd.Props["ip"] = ip
		}
		g.AddNode(nd)
		n++
	}
	add("domain:"+r.Domain, r.Domain, "")
	for _, rec := range r.Records {
		if rec.Type != "A" && rec.Type != "AAAA" {
			continue
		}
		host := rec.Name
		if host == r.Domain {
			host = "www." + r.Domain
		}
		add("domain:"+host, host, rec.Value)
	}
	return n, nil
}
