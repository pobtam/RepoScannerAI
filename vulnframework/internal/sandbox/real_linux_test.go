//go:build sandboxprobe && linux

package sandbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/sandbox"
)

// The orphan-pipe hazard, OQ-P10b-02.
//
// In its own file under `sandboxprobe && linux` rather than guarded by a
// runtime check, for the same reason the whole probe suite is build-tagged: on
// macOS this test must be ABSENT, not skipped and not failing. `sh` execs
// `sleep` directly there rather than forking, so there is no orphan to leave
// behind and nothing to observe — and a test that cannot observe its subject
// must not appear in a run at all, in either colour.
//
// Recorded as honest coverage debt since Phase 10b. This is the file that
// answers it, on the platform where the hazard exists.

// TestTheProcessGroupIsKilledWithTheParent is OQ-P10b-02.
//
// What it is about: killing the process the harness was handed is not enough.
// An orphaned grandchild keeps the output pipes open, so Wait blocks on the
// pipes rather than the process, and an agent that shelled out to anything at
// all outlives its budget indefinitely while the harness believes it has
// already stopped it. The budget test found this taking thirty seconds to
// enforce a three-hundred-millisecond deadline.
func TestTheProcessGroupIsKilledWithTheParent(t *testing.T) {
	backend := requireRealBackend(t)

	s, err := sandbox.New(realPolicy(t), sandbox.Options{})
	if err != nil {
		t.Fatalf("building the real sandbox: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	// A shell that forks a long-lived child and then waits: killing only the
	// shell leaves the child holding the pipes.
	cmd, err := s.Command(ctx, "sh", "-c", "sleep 600 & sleep 600")
	if err != nil {
		t.Fatalf("building the command: %v", err)
	}

	start := time.Now()
	_ = cmd.Run()
	elapsed := time.Since(start)

	// Generous, because the point is orders of magnitude: the failure mode is
	// tens of seconds against a sub-second deadline.
	if elapsed > 10*time.Second {
		t.Fatalf("enforcing a 400ms deadline took %s on %s. An orphaned child is holding the "+
			"output pipes open, so the agent outlives its budget while the harness believes it "+
			"has stopped it (OQ-P10b-02)", elapsed, backend)
	}
	t.Logf("deadline enforced in %s", elapsed)
}
