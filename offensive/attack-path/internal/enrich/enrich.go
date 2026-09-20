// Copyright 2026 open-security-platform Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package enrich

import (
	"context"

	"github.com/Schildkrote/attack-path/internal/geo"
	"github.com/Schildkrote/attack-path/internal/graph"
	"github.com/Schildkrote/attack-path/internal/shodan"
)

// AddShodanExposures resolves dork via src and appends the resulting
// devices to g as exposure nodes. Node IDs are stable:
// "shodan:{ip}:{port}". Existing nodes are left untouched.
func AddShodanExposures(ctx context.Context, g *graph.Graph, src shodan.Source, dork string) (int, error) {
	devices, err := src.Query(ctx, dork)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range devices {
		id := "shodan:" + d.IP + ":" + itoa(d.Port)
		if g.HasNode(id) {
			continue
		}
		nd := graph.Node{
			ID:       id,
			Type:     graph.TypeExposure,
			Name:     d.Hostname + ":" + itoa(d.Port),
			Exposure: true,
			Props: map[string]string{
				"ip":      d.IP,
				"port":    itoa(d.Port),
				"product": d.Product,
				"version": d.Version,
				"os":      d.OS,
				"source":  "shodan:" + dork,
			},
		}
		g.AddNode(nd)
		n++
	}
	return n, nil
}

// AddGeoEnrichment walks g and, for every node whose "ip" or "phone" prop
// is set, attaches geo fields (country/city/asn) via lookup. Returns the
// number of nodes enriched. Nodes without matching geo data are skipped.
func AddGeoEnrichment(g *graph.Graph, lookup geo.Lookup) int {
	enriched := map[string]*graph.Node{}
	for _, node := range g.Nodes() {
		enriched[node.ID] = &node
	}
	n := 0
	for id, node := range enriched {
		ip, hasIP := node.Props["ip"]
		phone, hasPhone := node.Props["phone"]
		if !hasIP && !hasPhone {
			continue
		}
		var info geo.GeoInfo
		var ok bool
		if hasIP {
			info, ok = lookup.IP(ip)
		} else {
			info, ok = lookup.Phone(phone)
		}
		if !ok {
			continue
		}
		if node.Props == nil {
			node.Props = map[string]string{}
		}
		node.Props["geo_country"] = info.Country
		if info.City != "" {
			node.Props["geo_city"] = info.City
		}
		if info.ASN != "" {
			node.Props["geo_asn"] = info.ASN
		}
		if info.Org != "" {
			node.Props["geo_org"] = info.Org
		}
		g.AddNode(*node) // write back the enriched copy
		_ = id
		n++
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
