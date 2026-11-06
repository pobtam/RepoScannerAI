package nuguardfake_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
)

// Scripts registered twice for one repository answer in turn, and the last
// one repeats; a replay under the same key is still the same job.
func TestScriptsForOneRepositoryAnswerInTurn(t *testing.T) {
	fake := nuguardfake.New("k", "0.9.15")
	defer fake.Close()
	const url = "https://github.com/octo/app"
	fake.Script(url, &nuguardfake.Script{ErrorCode: "clone_failed"})
	fake.Script(url, &nuguardfake.Script{ErrorCode: "repo_too_large"})
	c := &nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return "k", nil },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }}
	codes := []string{}
	for i, key := range []string{"a", "a", "b", "c"} {
		job, err := c.Submit(context.Background(), nuguard.ScanCreateRequest{RepoURL: url, Ref: "x"}, key, nil)
		if err != nil {
			t.Fatalf("submission %d: %v", i, err)
		}
		codes = append(codes, job.Error.Code)
	}
	if want := "clone_failed clone_failed repo_too_large repo_too_large"; join(codes) != want {
		t.Errorf("codes %q, want %q", join(codes), want)
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}
