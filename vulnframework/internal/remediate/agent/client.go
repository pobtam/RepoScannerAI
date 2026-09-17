package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/sandbox"
)

// Client is the headless model wrapper (VM-AD §11.4).
//
// The ordering inside Fix is the whole security posture, and it is this:
//
//  1. prove the sandbox — actually probe it, do not read its configuration;
//  2. only then ask for the credential;
//  3. run the model inside the sandbox;
//  4. parse strictly.
//
// Steps 1 and 2 are in that order because a credential handed to an unconfined
// process is a credential in reach of everything that process does, and by the
// time anything notices, the exfiltration has already happened. An
// implementation that read the key first and checked the boundary second would
// pass every behavioural test.
type Client struct {
	// Sandbox confines the model's process (VM-AD §15.2).
	Sandbox sandbox.Sandbox
	// Binary is the headless executable.
	Binary string
	Model  string

	// Credential is called ONLY after the sandbox has verified. A function
	// rather than a string so that "was the key ever fetched" is an
	// observable fact rather than an inference about field access.
	Credential func() (string, error)

	// ExtraArgs are appended to the invocation.
	ExtraArgs []string

	mu   sync.Mutex
	last Invocation
}

// Invocation records what was actually run, for assertions and for the audit
// trail. The prompt is retained because it is the thing that left the process.
type Invocation struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Prompt string
}

// LastCommand returns the most recent invocation.
func (c *Client) LastCommand() Invocation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Fix runs the model against the working tree.
func (c *Client) Fix(ctx context.Context, dir string, order remediate.WorkOrder) (Report, error) {
	if c.Sandbox == nil {
		return Report{}, &sandbox.ErrNotIsolated{
			Reason: "the client has no sandbox configured, so the model's process would be unconfined",
		}
	}

	// 1. Prove the boundary. Not "is it configured" — is it actually closed.
	if _, err := c.Sandbox.Verify(ctx); err != nil {
		return Report{}, err
	}

	// 2. Only now is a credential safe to hold.
	var key string
	if c.Credential != nil {
		k, err := c.Credential()
		if err != nil {
			return Report{}, fmt.Errorf("agent: obtaining the model credential: %w", err)
		}
		key = k
	}

	prompt := BuildPrompt(order)
	// The prompt leaves the process and reaches a third party, which is the
	// furthest anything in this system travels. It gets the same check as a
	// report or a ticket (VM-F-263).
	if err := model.AssertNoCredential("agent prompt", []byte(prompt)); err != nil {
		return Report{}, err
	}

	args := append([]string{
		"--print",
		"--output-format", "json",
		"--model", c.Model,
	}, c.ExtraArgs...)

	cmd, err := c.Sandbox.Command(ctx, c.Binary, args...)
	if err != nil {
		return Report{}, err
	}
	cmd.Stdin = strings.NewReader(prompt)
	if key != "" {
		// On the one channel the client controls, and deliberately not in the
		// prompt: a model can quote its prompt back, and an injected
		// instruction would ask it to.
		cmd.Env = append(cmd.Env, "ANTHROPIC_API_KEY="+key)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	c.mu.Lock()
	c.last = Invocation{Path: cmd.Path, Args: cmd.Args, Env: cmd.Env, Dir: cmd.Dir, Prompt: prompt}
	c.mu.Unlock()

	runErr := cmd.Run()
	if ctx.Err() != nil {
		// The harness's deadline reached the process, not just the wrapper.
		return Report{}, ctx.Err()
	}
	if runErr != nil {
		return Report{}, fmt.Errorf("agent: %s exited with error: %w: %s",
			c.Binary, runErr, excerpt(stderr.String()))
	}

	return ParseReport(stdout.Bytes())
}

// ParseReport reads the model's output strictly.
//
// Strictly, because the alternative is worse than an error. Prose, an empty
// buffer or a truncated object parsed leniently all produce an empty Report,
// which is indistinguishable from "the agent ran and correctly decided there
// was nothing to do" — and that silently consumes the finding's turn while
// reporting success.
func ParseReport(out []byte) (Report, error) {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return Report{}, fmt.Errorf("agent: produced no output. An empty result is not an empty " +
			"success: it is indistinguishable from a clean no-op, and treating it as one consumes the " +
			"finding's turn while reporting that nothing needed doing")
	}
	if trimmed[0] != '{' {
		return Report{}, fmt.Errorf("agent: output is not a JSON object (starts with %q): %s",
			string(trimmed[0]), excerpt(string(trimmed)))
	}

	var report Report
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		// Unknown fields are tolerated — a model adding a field is not a
		// failure — but malformed JSON is not.
		var lenient Report
		if jerr := json.Unmarshal(trimmed, &lenient); jerr != nil {
			return Report{}, fmt.Errorf("agent: unparseable output: %w: %s", jerr, excerpt(string(trimmed)))
		}
		report = lenient
	}
	if report.Iterations <= 0 {
		report.Iterations = 1
	}
	return report, nil
}

func excerpt(s string) string {
	const limit = 240
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

var _ = exec.Command
