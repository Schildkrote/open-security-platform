// Copyright 2026 open-decision-platform Authors.
// SPDX-License-Identifier: Apache-2.0

package ontology

// Durable SQLite persistence behind the same Snapshot contract as
// SaveJSON/LoadJSON. The ontology stays the single source of truth; SQLite
// is the on-disk store. Uses modernc.org/sqlite (pure Go, offline CI).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the SQLite schema generation.
const SchemaVersion = 1

func sqliteMigrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	classification TEXT NOT NULL DEFAULT '',
	properties TEXT NOT NULL DEFAULT '{}',
	provenance TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	from_id TEXT NOT NULL,
	to_id TEXT NOT NULL,
	properties TEXT NOT NULL DEFAULT '{}',
	provenance TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_type ON objects(type);
CREATE INDEX IF NOT EXISTS idx_links_from ON links(from_id);
CREATE INDEX IF NOT EXISTS idx_links_to ON links(to_id);
`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)`, fmt.Sprintf("%d", SchemaVersion))
	return err
}

// SaveSQLite writes the full store to a SQLite file (objects + links + meta).
// The file is replaced atomically: write to a temp path, then rename.
func (s *Store) SaveSQLite(path string) error {
	s.mu.RLock()
	snap := Snapshot{}
	for _, o := range s.Objects {
		snap.Objects = append(snap.Objects, cloneObject(o))
	}
	for _, l := range s.Links {
		snap.Links = append(snap.Links, cloneLink(l))
	}
	s.mu.RUnlock()
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].ID < snap.Objects[j].ID })
	sort.Slice(snap.Links, func(i, j int) bool { return snap.Links[i].ID < snap.Links[j].ID })

	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := sqliteMigrate(db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM objects`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM links`); err != nil {
		tx.Rollback()
		return err
	}
	for _, o := range snap.Objects {
		props, _ := json.Marshal(o.Properties)
		prov, _ := json.Marshal(o.Provenance)
		if _, err := tx.Exec(
			`INSERT INTO objects (id, type, classification, properties, provenance, created_at, updated_at) VALUES (?,?,?,?,?,?,?)`,
			o.ID, o.Type, o.Classification, string(props), string(prov),
			o.CreatedAt.Format(time.RFC3339Nano), o.UpdatedAt.Format(time.RFC3339Nano),
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, l := range snap.Links {
		props, _ := json.Marshal(l.Properties)
		prov, _ := json.Marshal(l.Provenance)
		if _, err := tx.Exec(
			`INSERT INTO links (id, type, from_id, to_id, properties, provenance, created_at) VALUES (?,?,?,?,?,?,?)`,
			l.ID, l.Type, l.From, l.To, string(props), string(prov), l.CreatedAt.Format(time.RFC3339Nano),
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadSQLite reads a store produced by SaveSQLite.
func LoadSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	s := NewStore()

	rows, err := db.Query(
		`SELECT id, type, classification, properties, provenance, created_at, updated_at FROM objects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, typ, class string
			props, prov    string
			created, updat string
		)
		if err := rows.Scan(&id, &typ, &class, &props, &prov, &created, &updat); err != nil {
			return nil, err
		}
		o := Object{ID: id, Type: typ, Classification: class}
		_ = json.Unmarshal([]byte(props), &o.Properties)
		_ = json.Unmarshal([]byte(prov), &o.Provenance)
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			o.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339Nano, updat); err == nil {
			o.UpdatedAt = t
		}
		if _, err := s.UpsertObject(o); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	lrows, err := db.Query(
		`SELECT id, type, from_id, to_id, properties, provenance, created_at FROM links ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer lrows.Close()
	for lrows.Next() {
		var (
			id, typ, from, to string
			props, prov       string
			created           string
		)
		if err := lrows.Scan(&id, &typ, &from, &to, &props, &prov, &created); err != nil {
			return nil, err
		}
		l := Link{ID: id, Type: typ, From: from, To: to}
		_ = json.Unmarshal([]byte(props), &l.Properties)
		_ = json.Unmarshal([]byte(prov), &l.Provenance)
		if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
			l.CreatedAt = t
		}
		if _, err := s.AddLink(l); err != nil {
			return nil, err
		}
	}
	return s, lrows.Err()
}
