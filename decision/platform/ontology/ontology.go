// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ontology is a minimal decision-centric object/link store.
// Objects are first-class nouns; links are typed directed edges; both
// carry provenance. This is the open core of a Palantir-style Ontology,
// not a thin semantic layer over a lake.
package ontology

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Built-in object type names used across connectors.
const (
	TypePerson       = "Person"
	TypeOrganization = "Organization"
	TypeEvent        = "Event"
	TypeLocation     = "Location"
	TypeAsset        = "Asset"
	TypeDocument     = "Document"
	TypeCase         = "Case"
	TypeWarrant      = "Warrant"
	TypeVehicle      = "Vehicle"
	TypePlateRead    = "PlateRead"
	TypeSensor       = "Sensor"
	TypeFinding      = "Finding"
	TypeBiometricHit = "BiometricHit"
	TypeAlert        = "Alert"
)

// Link type names.
const (
	LinkAssociatedWith = "associated_with"
	LinkLocatedAt      = "located_at"
	LinkEmployedBy     = "employed_by"
	LinkMemberOf       = "member_of"
	LinkObservedAt     = "observed_at"
	LinkMatchedHotlist = "matched_hotlist"
	LinkSameAs         = "same_as"
	LinkEvidenceIn     = "evidence_in"
	LinkIssuedFor      = "issued_for"
	LinkCapturedBy     = "captured_by"
	LinkDerivedFrom    = "derived_from"
)

// ObjectType describes a noun in the twin.
type ObjectType struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"` // name → kind
}

// LinkType describes a directed relationship.
type LinkType struct {
	Name        string `json:"name"`
	FromType    string `json:"from_type"` // empty = any
	ToType      string `json:"to_type"`
	Description string `json:"description,omitempty"`
}

// Provenance records how an object/link was hydrated.
type Provenance struct {
	Source     string    `json:"source"`
	ExternalID string    `json:"external_id,omitempty"`
	IngestedAt time.Time `json:"ingested_at"`
	Pipeline   string    `json:"pipeline,omitempty"`
}

// Object is a first-class entity.
type Object struct {
	ID             string         `json:"id"` // e.g. person:alice
	Type           string         `json:"type"`
	Properties     map[string]any `json:"properties,omitempty"`
	Classification string         `json:"classification,omitempty"` // public|internal|restricted|secret
	Provenance     Provenance     `json:"provenance"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Link is a typed directed edge.
type Link struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	Properties map[string]any `json:"properties,omitempty"`
	Provenance Provenance     `json:"provenance"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Registry holds object/link type definitions (OMS-lite).
type Registry struct {
	mu      sync.RWMutex
	objects map[string]ObjectType
	links   map[string]LinkType
}

// NewRegistry with built-in LE / security / biometric types.
func NewRegistry() *Registry {
	r := &Registry{
		objects: map[string]ObjectType{},
		links:   map[string]LinkType{},
	}
	builtins := []ObjectType{
		{Name: TypePerson, Description: "Natural person (pseudonymous id preferred)"},
		{Name: TypeOrganization},
		{Name: TypeEvent},
		{Name: TypeLocation},
		{Name: TypeAsset},
		{Name: TypeDocument},
		{Name: TypeCase, Description: "Investigative or protective case file"},
		{Name: TypeWarrant},
		{Name: TypeVehicle},
		{Name: TypePlateRead, Description: "ALPR observation event"},
		{Name: TypeSensor, Description: "Camera, ALPR unit, mic, drone"},
		{Name: TypeFinding, Description: "OSP / OSINT finding"},
		{Name: TypeBiometricHit, Description: "OBP match event (no raw biometrics)"},
		{Name: TypeAlert},
	}
	for _, t := range builtins {
		r.objects[t.Name] = t
	}
	linkDefs := []LinkType{
		{Name: LinkAssociatedWith},
		{Name: LinkLocatedAt, ToType: TypeLocation},
		{Name: LinkEmployedBy, FromType: TypePerson, ToType: TypeOrganization},
		{Name: LinkMemberOf},
		{Name: LinkObservedAt, FromType: TypeVehicle, ToType: TypeLocation},
		{Name: LinkMatchedHotlist, FromType: TypePlateRead},
		{Name: LinkSameAs},
		{Name: LinkEvidenceIn, ToType: TypeCase},
		{Name: LinkIssuedFor, FromType: TypeWarrant},
		{Name: LinkCapturedBy, ToType: TypeSensor},
		{Name: LinkDerivedFrom},
	}
	for _, l := range linkDefs {
		r.links[l.Name] = l
	}
	return r
}

func (r *Registry) ObjectType(name string) (ObjectType, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.objects[name]
	return t, ok
}

func (r *Registry) RegisterObject(t ObjectType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objects[t.Name] = t
}

func (r *Registry) RegisterLink(t LinkType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links[t.Name] = t
}

// Store is an in-memory object database (Phonograph-lite).
type Store struct {
	mu        sync.RWMutex
	Registry  *Registry
	Objects   map[string]*Object
	Links     map[string]*Link
	fromIndex map[string][]string // object id → link ids
	toIndex   map[string][]string
}

// NewStore creates an empty store with default registry.
func NewStore() *Store {
	return &Store{
		Registry:  NewRegistry(),
		Objects:   map[string]*Object{},
		Links:     map[string]*Link{},
		fromIndex: map[string][]string{},
		toIndex:   map[string][]string{},
	}
}

// MakeID builds type:key identifiers.
func MakeID(typeName, key string) string {
	key = strings.TrimSpace(key)
	typeName = strings.TrimSpace(typeName)
	return strings.ToLower(typeName) + ":" + key
}

// UpsertObject inserts or merges properties.
func (s *Store) UpsertObject(o Object) (*Object, error) {
	if o.ID == "" {
		return nil, fmt.Errorf("object id required")
	}
	if o.Type == "" {
		return nil, fmt.Errorf("object type required")
	}
	if _, ok := s.Registry.ObjectType(o.Type); !ok {
		return nil, fmt.Errorf("unknown object type %q", o.Type)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.Objects[o.ID]; ok {
		if o.Properties != nil {
			if existing.Properties == nil {
				existing.Properties = map[string]any{}
			}
			for k, v := range o.Properties {
				existing.Properties[k] = v
			}
		}
		if o.Classification != "" {
			existing.Classification = o.Classification
		}
		if o.Provenance.Source != "" {
			existing.Provenance = o.Provenance
		}
		existing.UpdatedAt = now
		return cloneObject(existing), nil
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = now
	}
	o.UpdatedAt = now
	if o.Properties == nil {
		o.Properties = map[string]any{}
	}
	if o.Classification == "" {
		o.Classification = "internal"
	}
	if o.Provenance.IngestedAt.IsZero() {
		o.Provenance.IngestedAt = now
	}
	cp := o
	s.Objects[o.ID] = &cp
	return cloneObject(&cp), nil
}

// AddLink creates a directed link.
func (s *Store) AddLink(l Link) (*Link, error) {
	if l.From == "" || l.To == "" {
		return nil, fmt.Errorf("link from/to required")
	}
	if l.Type == "" {
		return nil, fmt.Errorf("link type required")
	}
	if _, ok := s.Registry.links[l.Type]; !ok {
		// allow unknown link types but register lightly
		s.Registry.RegisterLink(LinkType{Name: l.Type})
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Objects[l.From]; !ok {
		return nil, fmt.Errorf("from object %s missing", l.From)
	}
	if _, ok := s.Objects[l.To]; !ok {
		return nil, fmt.Errorf("to object %s missing", l.To)
	}
	if l.ID == "" {
		l.ID = fmt.Sprintf("link:%s:%s:%s:%d", l.Type, l.From, l.To, now.UnixNano())
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	if l.Provenance.IngestedAt.IsZero() {
		l.Provenance.IngestedAt = now
	}
	if l.Properties == nil {
		l.Properties = map[string]any{}
	}
	cp := l
	s.Links[l.ID] = &cp
	s.fromIndex[l.From] = append(s.fromIndex[l.From], l.ID)
	s.toIndex[l.To] = append(s.toIndex[l.To], l.ID)
	return cloneLink(&cp), nil
}

// Get returns an object by id.
func (s *Store) Get(id string) (*Object, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.Objects[id]
	if !ok {
		return nil, false
	}
	return cloneObject(o), true
}

// Query filter.
type Query struct {
	Type           string
	Classification string
	PropertyEq     map[string]any
	Limit          int
}

// QueryObjects returns matching objects.
func (s *Store) QueryObjects(q Query) []*Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Object
	for _, o := range s.Objects {
		if q.Type != "" && o.Type != q.Type {
			continue
		}
		if q.Classification != "" && o.Classification != q.Classification {
			continue
		}
		ok := true
		for k, v := range q.PropertyEq {
			if o.Properties[k] != v {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, cloneObject(o))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

// Neighbors returns links from an object (outgoing) and optionally incoming.
func (s *Store) Neighbors(id string, incoming bool) []*Link {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []string
	ids = append(ids, s.fromIndex[id]...)
	if incoming {
		ids = append(ids, s.toIndex[id]...)
	}
	out := make([]*Link, 0, len(ids))
	seen := map[string]bool{}
	for _, lid := range ids {
		if seen[lid] {
			continue
		}
		seen[lid] = true
		if l, ok := s.Links[lid]; ok {
			out = append(out, cloneLink(l))
		}
	}
	return out
}

// Expand BFS up to depth.
func (s *Store) Expand(start string, depth int) (objs []*Object, links []*Link) {
	if depth < 0 {
		depth = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seenO := map[string]bool{}
	seenL := map[string]bool{}
	type item struct {
		id    string
		depth int
	}
	q := []item{{start, 0}}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if seenO[cur.id] {
			continue
		}
		seenO[cur.id] = true
		if o, ok := s.Objects[cur.id]; ok {
			objs = append(objs, cloneObject(o))
		}
		if cur.depth >= depth {
			continue
		}
		for _, lid := range append(s.fromIndex[cur.id], s.toIndex[cur.id]...) {
			l, ok := s.Links[lid]
			if !ok || seenL[lid] {
				continue
			}
			seenL[lid] = true
			links = append(links, cloneLink(l))
			next := l.To
			if l.To == cur.id {
				next = l.From
			}
			q = append(q, item{next, cur.depth + 1})
		}
	}
	return objs, links
}

// Path finds a short path between two object ids (BFS).
func (s *Store) Path(from, to string, maxDepth int) []*Link {
	if maxDepth <= 0 {
		maxDepth = 6
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if from == to {
		return nil
	}
	type node struct {
		id   string
		path []*Link
	}
	q := []node{{from, nil}}
	seen := map[string]bool{from: true}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if len(cur.path) >= maxDepth {
			continue
		}
		for _, lid := range append(s.fromIndex[cur.id], s.toIndex[cur.id]...) {
			l := s.Links[lid]
			if l == nil {
				continue
			}
			next := l.To
			if l.To == cur.id {
				next = l.From
			}
			if seen[next] {
				continue
			}
			np := append(append([]*Link{}, cur.path...), cloneLink(l))
			if next == to {
				return np
			}
			seen[next] = true
			q = append(q, node{next, np})
		}
	}
	return nil
}

// Snapshot is serializable store state.
type Snapshot struct {
	Objects []*Object `json:"objects"`
	Links   []*Link   `json:"links"`
}

// SaveJSON writes the store.
func (s *Store) SaveJSON(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{}
	for _, o := range s.Objects {
		snap.Objects = append(snap.Objects, cloneObject(o))
	}
	for _, l := range s.Links {
		snap.Links = append(snap.Links, cloneLink(l))
	}
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].ID < snap.Objects[j].ID })
	sort.Slice(snap.Links, func(i, j int) bool { return snap.Links[i].ID < snap.Links[j].ID })
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadJSON replaces store contents from path.
func LoadJSON(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, err
	}
	s := NewStore()
	for _, o := range snap.Objects {
		if o == nil {
			continue
		}
		if _, err := s.UpsertObject(*o); err != nil {
			return nil, err
		}
	}
	for _, l := range snap.Links {
		if l == nil {
			continue
		}
		if _, err := s.AddLink(*l); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func cloneObject(o *Object) *Object {
	if o == nil {
		return nil
	}
	cp := *o
	if o.Properties != nil {
		cp.Properties = map[string]any{}
		for k, v := range o.Properties {
			cp.Properties[k] = v
		}
	}
	return &cp
}

func cloneLink(l *Link) *Link {
	if l == nil {
		return nil
	}
	cp := *l
	if l.Properties != nil {
		cp.Properties = map[string]any{}
		for k, v := range l.Properties {
			cp.Properties[k] = v
		}
	}
	return &cp
}
