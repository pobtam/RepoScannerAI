package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

// Per-repository remediation serialisation (OQ-P4-02, VM-AD §7.3, VM-F-503).
//
// Two concurrent remediation jobs on one repository produce conflicting
// branches and duplicate pull requests. The lock that prevents it is a STORE
// ROW with an expiry, not `pg_advisory_lock`, for two reasons recorded in §7.3:
//
//	An advisory lock is held by a Postgres session, so it cannot exist in the
//	in-memory backend at all. The fake would then enforce weaker rules than
//	production, which makes every test that uses it a statement about the fake.
//
//	An advisory lock dies with its session in ways the store cannot see. A lock
//	row with an expiry gives the same mutual exclusion plus crash safety: the
//	sweeper reclaims it exactly as it reverts an expired finding lease.
//
// So the lock is held to the conformance suite, like everything else.

func lockRepo(t *testing.T, s store.Store) {
	t.Helper()
	seedRepo(t, s)
}

func TestRepoLockIsMutuallyExclusive(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		expiry := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

		if err := s.AcquireRepoLock(ctx, testRepo, "worker-a", expiry); err != nil {
			t.Fatalf("first acquisition: %v", err)
		}

		err := s.AcquireRepoLock(ctx, testRepo, "worker-b", expiry)
		if err == nil {
			t.Fatal("two workers hold the same repository lock; they would push conflicting branches (VM-F-503)")
		}
		if !errors.Is(err, store.ErrRepoLocked) {
			t.Errorf("error is %v, want ErrRepoLocked so the caller can defer rather than fail", err)
		}

		// The holder is named, so an operator can see which worker has it.
		held, err := s.GetRepoLock(ctx, testRepo)
		if err != nil {
			t.Fatalf("GetRepoLock: %v", err)
		}
		if held.Owner != "worker-a" {
			t.Errorf("owner = %q, want worker-a", held.Owner)
		}
		if held.ExpiresAt == nil || !held.ExpiresAt.Equal(expiry) {
			t.Errorf("expires_at = %v, want %v", held.ExpiresAt, expiry)
		}
	})
}

// TestRepoLockIsReentrantForItsOwner covers the retry case. A worker that
// re-acquires its own lock — after a transient failure, or because the harness
// batches a second fix group — must not deadlock against itself.
func TestRepoLockIsReentrantForItsOwner(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		first := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

		if err := s.AcquireRepoLock(ctx, testRepo, "worker-a", first); err != nil {
			t.Fatalf("acquire: %v", err)
		}
		extended := first.Add(10 * time.Minute)
		if err := s.AcquireRepoLock(ctx, testRepo, "worker-a", extended); err != nil {
			t.Fatalf("the owner could not re-acquire its own lock: %v", err)
		}
		held, _ := s.GetRepoLock(ctx, testRepo)
		if held.ExpiresAt == nil || !held.ExpiresAt.Equal(extended) {
			t.Errorf("re-acquisition did not extend the expiry: %v, want %v", held.ExpiresAt, extended)
		}
	})
}

// TestExpiredRepoLockIsReclaimed is the crash-safety clause. A worker killed
// mid-flight must not strand the repository: without expiry, one OOM-killed pod
// means that repository is never remediated again and nothing reports why.
func TestExpiredRepoLockIsReclaimed(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		expiry := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		after := expiry.Add(time.Second)

		if err := s.AcquireRepoLock(ctx, testRepo, "crashed-worker", expiry); err != nil {
			t.Fatalf("acquire: %v", err)
		}

		// Before expiry the lock still holds.
		if err := s.AcquireRepoLockAt(ctx, testRepo, "worker-b", expiry.Add(time.Hour), expiry.Add(-time.Second)); err == nil {
			t.Error("an unexpired lock was taken from its holder")
		}

		// The sweeper reclaims it, and says so.
		n, err := s.SweepExpiredRepoLocks(ctx, after)
		if err != nil {
			t.Fatalf("SweepExpiredRepoLocks: %v", err)
		}
		if n != 1 {
			t.Errorf("swept %d locks, want 1", n)
		}
		if err := s.AcquireRepoLockAt(ctx, testRepo, "worker-b", after.Add(time.Hour), after); err != nil {
			t.Fatalf("the repository is stranded after its holder crashed: %v", err)
		}

		// Acquisition alone also reclaims: a worker must not have to wait for a
		// sweeper cycle to take a lock nobody holds any more.
		if err := s.ReleaseRepoLock(ctx, testRepo, "worker-b"); err != nil {
			t.Fatalf("release: %v", err)
		}
		if err := s.AcquireRepoLockAt(ctx, testRepo, "worker-c", after.Add(time.Hour), after); err != nil {
			t.Fatalf("acquire after release: %v", err)
		}
		stale := after.Add(2 * time.Hour)
		if err := s.AcquireRepoLockAt(ctx, testRepo, "worker-d", stale.Add(time.Hour), stale); err != nil {
			t.Errorf("acquisition did not reclaim an expired lock without a sweep: %v", err)
		}
	})
}

// TestReleaseRequiresOwnership stops one worker releasing another's lock, which
// would silently reintroduce the concurrency the lock exists to prevent — and
// would do it at the worst moment, mid-remediation.
func TestReleaseRequiresOwnership(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		expiry := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

		if err := s.AcquireRepoLock(ctx, testRepo, "worker-a", expiry); err != nil {
			t.Fatalf("acquire: %v", err)
		}
		if err := s.ReleaseRepoLock(ctx, testRepo, "worker-b"); err == nil {
			t.Error("worker-b released worker-a's lock; the repository would then have two active workers")
		}
		held, _ := s.GetRepoLock(ctx, testRepo)
		if held.Owner != "worker-a" {
			t.Errorf("owner = %q after a foreign release, want worker-a", held.Owner)
		}
	})
}

// TestConcurrentAcquisitionElectsOneWinner is the clause that matters in
// production. Ten workers, one repository, one winner — and the count has to
// come from the store, not from a mutex in the test.
func TestConcurrentAcquisitionElectsOneWinner(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		expiry := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

		const workers = 10
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners []string
		)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				owner := "worker-" + string(rune('a'+i))
				err := s.AcquireRepoLock(ctx, testRepo, owner, expiry)
				if err == nil {
					mu.Lock()
					winners = append(winners, owner)
					mu.Unlock()
					return
				}
				if !errors.Is(err, store.ErrRepoLocked) {
					t.Errorf("worker %s got an unexpected error: %v", owner, err)
				}
			}(i)
		}
		wg.Wait()

		if len(winners) != 1 {
			t.Fatalf("%d workers acquired the lock: %v; two remediation jobs on one repository "+
				"produce conflicting branches and duplicate pull requests (VM-F-503)", len(winners), winners)
		}
		held, err := s.GetRepoLock(ctx, testRepo)
		if err != nil {
			t.Fatalf("GetRepoLock: %v", err)
		}
		if held.Owner != winners[0] {
			t.Errorf("the store holds %q but %q believes it won", held.Owner, winners[0])
		}
	})
}

// TestDifferentReposDoNotBlockEachOther is the other half of VM-F-503:
// serialised WITHIN a repository, parallel ACROSS them. A lock that serialised
// the fleet would make remediation useless at any real scale.
func TestDifferentReposDoNotBlockEachOther(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		lockRepo(t, s)
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: "org/other", Tier: 2, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		expiry := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

		if err := s.AcquireRepoLock(ctx, testRepo, "worker-a", expiry); err != nil {
			t.Fatalf("acquire first repo: %v", err)
		}
		if err := s.AcquireRepoLock(ctx, "org/other", "worker-b", expiry); err != nil {
			t.Errorf("a lock on one repository blocked another: %v", err)
		}
	})
}
