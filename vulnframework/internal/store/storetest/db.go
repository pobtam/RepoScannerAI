// Package storetest opens isolated Postgres databases for tests.
//
// `go test ./...` runs packages in parallel. Two packages resetting and
// migrating the same database interfere in ways that look like real failures —
// a schema dropped out from under another package's query — and the resulting
// flakiness is far more expensive than the isolation costs. Each package gets
// its own database instead.
package storetest

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// EnvDSN is the environment variable naming the administrative connection.
const EnvDSN = "VULNFRAMEWORK_TEST_DSN"

var safeName = regexp.MustCompile(`[^a-z0-9_]+`)

// OpenDB returns a connection to a database dedicated to the named suite,
// creating it if necessary. It skips the test when no DSN is configured, so the
// offline suite still passes.
//
// The returned database is empty of this project's schema; callers migrate it.
func OpenDB(t *testing.T, suite string) *sql.DB {
	t.Helper()

	admin := os.Getenv(EnvDSN)
	if admin == "" {
		t.Skipf("%s not set: skipping the Postgres backend", EnvDSN)
	}

	name := "vftest_" + safeName.ReplaceAllString(strings.ToLower(suite), "_")
	if err := ensureDatabase(admin, name); err != nil {
		t.Fatalf("preparing test database %s: %v", name, err)
	}

	dsn, err := withDatabase(admin, name)
	if err != nil {
		t.Fatalf("building dsn: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ensureDatabase creates the database if it does not already exist.
func ensureDatabase(adminDSN, name string) error {
	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return err
	}
	defer admin.Close()

	var exists bool
	if err := admin.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	// CREATE DATABASE cannot be parameterised; the name is derived from a Go
	// identifier and filtered to [a-z0-9_], so there is nothing to inject.
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		// A concurrent package may have won the race; that is fine.
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	return nil
}

// withDatabase rewrites a DSN to point at a different database.
func withDatabase(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parsing dsn: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// FreshDSN returns a connection string for an EMPTY database of the suite's
// own, recreating it if a previous run left one behind. It is for tests that
// drive a compiled program, which needs a DSN rather than a handle. Like
// OpenDB it skips unless EnvDSN is set, and it only ever touches databases
// named vftest_*.
func FreshDSN(t *testing.T, suite string) string {
	t.Helper()
	admin := os.Getenv(EnvDSN)
	if admin == "" {
		t.Skipf("%s not set: skipping the Postgres backend", EnvDSN)
	}
	name := "vftest_" + safeName.ReplaceAllString(strings.ToLower(suite), "_")
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The name is derived from a Go identifier and filtered to [a-z0-9_].
	if _, err := db.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
		t.Fatalf("dropping %s: %v", name, err)
	}
	if err := ensureDatabase(admin, name); err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	dsn, err := withDatabase(admin, name)
	if err != nil {
		t.Fatal(err)
	}
	return dsn
}
