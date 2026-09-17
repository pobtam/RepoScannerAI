package sandbox

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// waitDelay bounds how long Wait will block after the context is cancelled.
//
// Without it, killing the agent is not enough. Go's Wait blocks until the
// output pipes close, and an orphaned grandchild holds them open — so an agent
// that shells out to anything at all outlives its budget indefinitely while
// the harness sits in Wait believing it has already stopped it.
const waitDelay = 2 * time.Second

// contain makes a command killable as a whole tree.
//
// Two separate problems, both of which let an agent outlive its budget:
//
// A process group, because the agent spawns children. Killing only the
// process it was handed leaves `sleep`, a compiler, or a second model call
// running with the same credentials and the same filesystem access, no longer
// attached to anything that is watching.
//
// A wait delay, because even a killed process leaves its pipes held open by
// those children, and Wait blocks on the pipes rather than on the process.
// This was not theoretical: the budget test found it taking thirty seconds to
// enforce a three-hundred-millisecond deadline.
func contain(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The negative pid addresses the whole group.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return fmt.Errorf("sandbox: killing the agent process group: %w", err)
		}
		return nil
	}
	cmd.WaitDelay = waitDelay
}
