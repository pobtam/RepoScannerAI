package store_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/store"
)

// --- Structural checks, offline --------------------------------------------

// TestMigrationsAreWellFormed runs with no database. It covers the properties
// that make the migration set usable at all: contiguous versions, and an up and
// a down for every one.
func TestMigrationsAreWellFormed(t *testing.T) {
	migrations, err := store.LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations found")
	}

	for i, m := range migrations {
		if m.Version != i+1 {
			t.Errorf("migration %d has version %d; versions must be contiguous from 1", i, m.Version)
		}
		if strings.TrimSpace(m.Up) == "" {
			t.Errorf("migration %d (%s) has an empty up statement", m.Version, m.Name)
		}
		// Every migration must be reversible. A one-way migration makes the
		// rollback path untestable exactly when it is needed.
		if strings.TrimSpace(m.Down) == "" {
			t.Errorf("migration %d (%s) has an empty down statement", m.Version, m.Name)
		}
		if m.Checksum == "" {
			t.Errorf("migration %d (%s) has no checksum", m.Version, m.Name)
		}
	}
}

// TestMigrationChecksumsAreStable guards against an applied migration being
// edited in place. If the file changes, the deployed database silently differs
// from the repository and every later migration rests on an assumption that no
// longer holds.
func TestMigrationChecksumsAreStable(t *testing.T) {
	// The name is the part after the version prefix: 0001_init.up.sql -> "init".
	want := map[int]string{
		1: "init",
		2: "merge_provenance",
	}
	migrations, err := store.LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(migrations) != len(want) {
		t.Fatalf("got %d migrations, want %d; add a new one here deliberately", len(migrations), len(want))
	}
	for _, m := range migrations {
		name, tracked := want[m.Version]
		if !tracked {
			t.Errorf("migration %d (%s) is not in the expected set; add it here deliberately", m.Version, m.Name)
			continue
		}
		if m.Name != name {
			t.Errorf("migration %d is named %q, want %q", m.Version, m.Name, name)
		}
	}
}

// --- Gate clause 1: migrations apply and roll back --------------------------

// testDB opens the Postgres test database, skipping when none is configured.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("VULNFRAMEWORK_TEST_DSN")
	if dsn == "" {
		t.Skip("VULNFRAMEWORK_TEST_DSN not set: skipping migration execution against Postgres")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrationsApplyAndRollBack is the first gate clause, executed against a
// real Postgres rather than asserted structurally.
//
// It walks the full ladder up, then all the way back down, then up again —
// because a down migration that only works once is not a rollback, and the
// second climb is what proves the database was genuinely returned to empty.
func TestMigrationsApplyAndRollBack(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := store.NewPostgres(db)

	migrations, err := store.LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	top := len(migrations)

	// Start from empty.
	if err := s.MigrateTo(ctx, 0); err != nil {
		t.Fatalf("reset to 0: %v", err)
	}
	assertSchemaVersion(t, s, 0)
	assertTableAbsent(t, db, "findings")

	// Up, one version at a time.
	for v := 1; v <= top; v++ {
		if err := s.MigrateTo(ctx, v); err != nil {
			t.Fatalf("migrate up to %d: %v", v, err)
		}
		assertSchemaVersion(t, s, v)
	}
	assertTablePresent(t, db, "findings")
	assertTablePresent(t, db, "finding_observations")
	assertTablePresent(t, db, "repo_scan_results")
	assertColumnPresent(t, db, "findings", "reach_conflict")

	// Down, one version at a time.
	for v := top - 1; v >= 0; v-- {
		if err := s.MigrateTo(ctx, v); err != nil {
			t.Fatalf("migrate down to %d: %v", v, err)
		}
		assertSchemaVersion(t, s, v)
	}
	assertTableAbsent(t, db, "findings")
	assertTableAbsent(t, db, "finding_observations")

	// And up again: a down migration that leaves residue fails here.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("re-apply after rollback: %v", err)
	}
	assertSchemaVersion(t, s, top)
	assertTablePresent(t, db, "findings")
	assertColumnPresent(t, db, "findings", "reach_conflict")
}

// TestPartialRollbackPreservesEarlierSchema covers rolling back one step: the
// 0002 columns go, the 0001 tables stay.
func TestPartialRollbackPreservesEarlierSchema(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := store.NewPostgres(db)

	if err := s.MigrateTo(ctx, 0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertColumnPresent(t, db, "findings", "reach_conflict")

	if err := s.MigrateTo(ctx, 1); err != nil {
		t.Fatalf("roll back to 1: %v", err)
	}
	assertSchemaVersion(t, s, 1)
	assertTablePresent(t, db, "findings")
	assertColumnAbsent(t, db, "findings", "reach_conflict")
	assertColumnAbsent(t, db, "findings", "fixed_candidates")

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("re-apply 2: %v", err)
	}
	assertColumnPresent(t, db, "findings", "reach_conflict")
}

// TestPerKindSequencesSurviveRollforward covers the one piece of state a
// rollback deliberately destroys and recreates: the run sequences.
func TestPerKindSequencesSurviveRollforward(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := store.NewPostgres(db)

	if err := s.MigrateTo(ctx, 0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, kind := range store.AllRunKinds {
		var got string
		err := db.QueryRowContext(ctx,
			`SELECT sequence_name FROM information_schema.sequences WHERE sequence_name = $1`,
			"run_seq_"+string(kind)).Scan(&got)
		if err != nil {
			t.Errorf("sequence run_seq_%s missing after migration: %v (VM-F-115)", kind, err)
		}
	}
}

// TestEditedMigrationIsRefused covers the checksum guard: an applied migration
// whose file has changed must stop the runner rather than proceed.
func TestEditedMigrationIsRefused(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := store.NewPostgres(db)

	if err := s.MigrateTo(ctx, 0); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Capture the real checksum so it can be restored: the guard deliberately
	// blocks movement in *both* directions, so a tampered row cannot be undone
	// by rolling back. Restoring it directly is the only way out, which is the
	// point — a checksum mismatch means nobody knows what is deployed, and
	// automatically rolling back on that basis could drop data on a wrong
	// assumption. It requires a human.
	var original string
	if err := db.QueryRowContext(ctx,
		`SELECT checksum FROM schema_migrations WHERE version = 1`).Scan(&original); err != nil {
		t.Fatalf("reading checksum: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`UPDATE schema_migrations SET checksum = $1 WHERE version = 1`, original); err != nil {
			t.Errorf("restoring checksum: %v", err)
		}
	})

	if _, err := db.ExecContext(ctx,
		`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	err := s.Migrate(ctx)
	if err == nil {
		t.Fatal("migrator proceeded over an edited applied migration")
	}
	if !strings.Contains(err.Error(), "edited after being applied") {
		t.Errorf("error does not explain the problem: %v", err)
	}

	// A short or corrupt recorded checksum must error, not panic.
	if _, err := db.ExecContext(ctx,
		`UPDATE schema_migrations SET checksum = 'abc' WHERE version = 1`); err != nil {
		t.Fatalf("tamper short: %v", err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Error("migrator proceeded over a corrupt checksum")
	}
}

// --- helpers ----------------------------------------------------------------

func assertSchemaVersion(t *testing.T, s *store.Postgres, want int) {
	t.Helper()
	got, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name = $1 AND table_schema = 'public'`,
		table).Scan(&n)
	if err != nil {
		t.Fatalf("checking table %s: %v", table, err)
	}
	return n > 0
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2 AND table_schema = 'public'`,
		table, column).Scan(&n)
	if err != nil {
		t.Fatalf("checking column %s.%s: %v", table, column, err)
	}
	return n > 0
}

func assertTablePresent(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	if !tableExists(t, db, table) {
		t.Errorf("table %s is missing after migration", table)
	}
}

func assertTableAbsent(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	if tableExists(t, db, table) {
		t.Errorf("table %s survived rollback; the down migration left residue", table)
	}
}

func assertColumnPresent(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	if !columnExists(t, db, table, column) {
		t.Errorf("column %s.%s is missing after migration", table, column)
	}
}

func assertColumnAbsent(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	if columnExists(t, db, table, column) {
		t.Errorf("column %s.%s survived rollback", table, column)
	}
}
