package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is one reversible schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
	// Checksum covers the up statement. A migration that has already been
	// applied must never be edited in place: the applied database would then
	// silently differ from the file, and no later migration could be trusted.
	Checksum string
}

// LoadMigrations reads the embedded migration set, in ascending version order.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading migrations: %w", err)
	}

	type pair struct{ up, down string }
	byVersion := map[int]*pair{}
	names := map[int]string{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, direction, err := parseMigrationName(e.Name())
		if err != nil {
			return nil, err
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: reading %s: %w", e.Name(), err)
		}
		if byVersion[version] == nil {
			byVersion[version] = &pair{}
		}
		if prev, dup := names[version]; dup && prev != name {
			return nil, fmt.Errorf("store: version %d used by two migrations (%s and %s)", version, prev, name)
		}
		names[version] = name

		switch direction {
		case "up":
			byVersion[version].up = string(body)
		case "down":
			byVersion[version].down = string(body)
		}
	}

	versions := make([]int, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	out := make([]Migration, 0, len(versions))
	for i, v := range versions {
		// Versions must be contiguous from 1. A gap means a migration was
		// deleted rather than reversed, and the applied-version number would no
		// longer describe the schema.
		if v != i+1 {
			return nil, fmt.Errorf("store: migration versions are not contiguous: expected %d, found %d", i+1, v)
		}
		p := byVersion[v]
		if strings.TrimSpace(p.up) == "" {
			return nil, fmt.Errorf("store: migration %d (%s) has no up statement", v, names[v])
		}
		// Every migration must be reversible: the gate requires rollback, and a
		// one-way migration makes the rollback path untestable exactly when it
		// is needed.
		if strings.TrimSpace(p.down) == "" {
			return nil, fmt.Errorf("store: migration %d (%s) has no down statement; every migration must be reversible", v, names[v])
		}
		sum := sha256.Sum256([]byte(p.up))
		out = append(out, Migration{
			Version:  v,
			Name:     names[v],
			Up:       p.up,
			Down:     p.down,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	return out, nil
}

// parseMigrationName splits NNNN_name.(up|down).sql.
func parseMigrationName(filename string) (version int, name, direction string, err error) {
	base := strings.TrimSuffix(filename, ".sql")
	dot := strings.LastIndex(base, ".")
	if dot < 0 {
		return 0, "", "", fmt.Errorf("store: migration %q has no .up/.down suffix", filename)
	}
	direction = base[dot+1:]
	if direction != "up" && direction != "down" {
		return 0, "", "", fmt.Errorf("store: migration %q has direction %q, want up or down", filename, direction)
	}
	rest := base[:dot]
	under := strings.Index(rest, "_")
	if under < 0 {
		return 0, "", "", fmt.Errorf("store: migration %q is not NNNN_name.%s.sql", filename, direction)
	}
	version, err = strconv.Atoi(rest[:under])
	if err != nil {
		return 0, "", "", fmt.Errorf("store: migration %q has a non-numeric version: %w", filename, err)
	}
	if version < 1 {
		return 0, "", "", fmt.Errorf("store: migration %q has version %d; versions start at 1", filename, version)
	}
	return version, rest[under+1:], direction, nil
}

const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INT PRIMARY KEY,
  name       TEXT NOT NULL,
  checksum   TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// migrateTo brings a database to the target version, applying or reverting as
// needed. Version 0 is the empty database.
//
// Each step runs in its own transaction: a migration that fails half way leaves
// the database at the last complete version rather than in a state no version
// number describes.
func migrateTo(ctx context.Context, db *sql.DB, target int) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	if target < 0 || target > len(migrations) {
		return fmt.Errorf("store: target version %d is outside the available range 0..%d", target, len(migrations))
	}

	if _, err := db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("store: creating schema_migrations: %w", err)
	}

	current, err := schemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if err := verifyChecksums(ctx, db, migrations, current); err != nil {
		return err
	}

	for current < target {
		m := migrations[current]
		if err := applyStep(ctx, db, m, true); err != nil {
			return err
		}
		current = m.Version
	}
	for current > target {
		m := migrations[current-1]
		if err := applyStep(ctx, db, m, false); err != nil {
			return err
		}
		current = m.Version - 1
	}
	return nil
}

func applyStep(ctx context.Context, db *sql.DB, m Migration, up bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %d: %w", m.Version, err)
	}
	defer tx.Rollback()

	body, direction := m.Up, "up"
	if !up {
		body, direction = m.Down, "down"
	}
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("store: migration %d (%s) %s: %w", m.Version, m.Name, direction, err)
	}

	if up {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			m.Version, m.Name, m.Checksum)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, m.Version)
	}
	if err != nil {
		return fmt.Errorf("store: recording migration %d: %w", m.Version, err)
	}
	return tx.Commit()
}

// shortSum abbreviates a checksum for an error message without assuming it is
// well formed. A corrupt or truncated value in schema_migrations must produce a
// clear error, not a panic inside the code reporting the error.
func shortSum(s string) string {
	const n = 12
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func schemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: reading schema version: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// verifyChecksums refuses to proceed if an applied migration's file has been
// edited since it was applied. The database would silently differ from the
// repository, and every later migration would be built on an assumption that
// no longer holds.
func verifyChecksums(ctx context.Context, db *sql.DB, migrations []Migration, current int) error {
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()

	applied := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return fmt.Errorf("store: scanning applied migrations: %w", err)
		}
		applied[v] = sum
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, m := range migrations {
		want, ok := applied[m.Version]
		if !ok {
			continue
		}
		if want != m.Checksum {
			return fmt.Errorf(
				"store: migration %d (%s) was edited after being applied (recorded %s, file %s); "+
					"write a new migration instead of editing an applied one",
				m.Version, m.Name, shortSum(want), shortSum(m.Checksum))
		}
	}
	return nil
}
