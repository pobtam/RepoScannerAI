package envcanary

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// LeakCanary is the variable this fixture looks for.
//
// It is set in the worker's environment and deliberately left out of the
// sandbox's allowlist. A repository's own test suite must not be able to read
// it: a test process that can see the worker's environment can see whatever
// credentials the runner was launched with.
const LeakCanary = "VF_LEAKED_SECRET"

// TestTheWorkerEnvironmentDidNotLeakIn fails if the canary arrived.
//
// The assertion lives in the fixture rather than in the toolchain's test
// because this is the only place that can make it honestly. The question is
// what the repository's own code can actually SEE, and only the repository's
// own code can answer it. A test that inspected the toolchain's configuration
// instead would be asserting that the sandbox is configured, which is a
// different claim and the exact class of self-confirming check this build
// exists to remove.
//
// It reports names, never values: printing the value would copy whatever
// leaked into a test log.
func TestTheWorkerEnvironmentDidNotLeakIn(t *testing.T) {
	if _, present := os.LookupEnv(LeakCanary); present {
		t.Fatalf("%s reached the repository's test process: the worker's environment was not filtered. "+
			"Everything visible here: %s", LeakCanary, strings.Join(names(), ", "))
	}
}

func names() []string {
	var out []string
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			out = append(out, kv[:i])
		}
	}
	sort.Strings(out)
	return out
}
