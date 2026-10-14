package gh

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Discovery: which of the repositories a token reaches are scanned.
//
// Every repository the account can see is listed, and each is either
// included or skipped WITH A REASON. A repository that is silently left out
// is outside the coverage denominator, so the fleet would report complete
// coverage of a smaller fleet than the one that exists.

// Affiliation is how the account relates to a repository.
type Affiliation string

const (
	AffiliationOwner        Affiliation = "owner"
	AffiliationOrganization Affiliation = "organization"
	AffiliationCollaborator Affiliation = "collaborator"
)

// Skip reasons, in the order they are checked: the first that applies is the
// one reported.
const (
	SkipExcluded     = "excluded"
	SkipArchived     = "archived"
	SkipCollaborator = "collaborator"
	SkipFork         = "fork"
	SkipEmpty        = "empty"
	SkipTooLarge     = "too_large"
)

// DiscoverOptions decides what is scanned.
type DiscoverOptions struct {
	// IncludeCollaborator scans repositories the account is only a
	// collaborator on. Off by default: they are someone else's code.
	IncludeCollaborator bool
	// IncludeForks scans forks. Off by default: a fork's vulnerabilities are
	// usually its upstream's, reported there.
	IncludeForks bool
	// MaxSizeMB skips repositories GitHub estimates larger than this. Zero
	// means 1024.
	MaxSizeMB int
	// Excluded maps a repository to the reason a person excluded it.
	Excluded map[string]string
}

// Discovered is one repository and the decision about it.
type Discovered struct {
	Repo        AccountRepo `json:"repo"`
	Affiliation Affiliation `json:"affiliation"`
	Included    bool        `json:"included"`
	// Reason is one of the Skip constants when not included; Detail says it
	// in words.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Classify decides, for every repository the account can see, whether it is
// scanned. The result is sorted by name.
func Classify(account string, repos []AccountRepo, opts DiscoverOptions) []Discovered {
	maxKB := opts.MaxSizeMB
	if maxKB <= 0 {
		maxKB = 1024
	}
	maxKB *= 1024

	out := make([]Discovered, 0, len(repos))
	for _, r := range repos {
		d := Discovered{Repo: r, Affiliation: affiliationOf(account, r), Included: true}
		skip := func(reason, detail string) {
			if d.Included {
				d.Included, d.Reason, d.Detail = false, reason, detail
			}
		}
		if why, ok := opts.Excluded[r.FullName]; ok {
			skip(SkipExcluded, "excluded by a person: "+why)
		}
		if r.Archived {
			skip(SkipArchived, "archived on GitHub; nothing new can land in it")
		}
		if d.Affiliation == AffiliationCollaborator && !opts.IncludeCollaborator {
			skip(SkipCollaborator, "the account is only a collaborator; opt in with -include-collaborator")
		}
		if r.Fork && !opts.IncludeForks {
			skip(SkipFork, "a fork; opt in with -include-forks")
		}
		if r.SizeKB == 0 {
			skip(SkipEmpty, "empty: GitHub reports no content")
		}
		if r.SizeKB > maxKB {
			skip(SkipTooLarge, fmt.Sprintf("about %d MB, over the %d MB limit; raise it with -max-size-mb", r.SizeKB/1024, maxKB/1024))
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo.FullName < out[j].Repo.FullName })
	return out
}

func affiliationOf(account string, r AccountRepo) Affiliation {
	switch {
	case strings.EqualFold(r.Owner.Login, account):
		return AffiliationOwner
	case r.Owner.Type == "Organization":
		return AffiliationOrganization
	default:
		return AffiliationCollaborator
	}
}

// Lister is the one thing fleet sync needs from GitHub: the repositories in
// scope. The installed App satisfies it; so does a discovery result.
type Lister interface {
	Repositories(ctx context.Context) ([]RemoteRepo, error)
}

// IncludedRepos is a discovery result as a Lister: the included repositories
// only, so that a skipped one which is already registered is archived by
// fleet sync like any other repository that left scope.
type IncludedRepos []Discovered

func (d IncludedRepos) Repositories(context.Context) ([]RemoteRepo, error) {
	var out []RemoteRepo
	for _, x := range d {
		if !x.Included {
			continue
		}
		r := RemoteRepo{
			FullName: x.Repo.FullName, DefaultBranch: x.Repo.DefaultBranch,
			Archived: x.Repo.Archived, Private: x.Repo.Private,
		}
		if x.Repo.Language != "" {
			r.Languages = []string{strings.ToLower(x.Repo.Language)}
		}
		out = append(out, r)
	}
	return out, nil
}
