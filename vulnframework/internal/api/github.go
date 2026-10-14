package api

import (
	"net/http"
	"time"
)

// The GitHub account view: which account a token connected, when it
// expires, and every repository discovery saw with whether it is scanned.
// Read-only. Nothing here can carry the token: the store never holds it.

// GitHubView is the response of GET /v1/github.
type GitHubView struct {
	Connections []GitHubAccount  `json:"connections"`
	Discovered  []DiscoveredRepo `json:"discovered"`
	Exclusions  []ExcludedRepo   `json:"exclusions"`
	Summary     DiscoverySummary `json:"summary"`
}

// GitHubAccount is one connected account.
type GitHubAccount struct {
	Account   string     `json:"account"`
	Kind      string     `json:"kind"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// ExpiresInDays is whole days from now; negative once expired. Absent
	// when GitHub reported no expiry.
	ExpiresInDays *int      `json:"expires_in_days,omitempty"`
	ReadOnly      string    `json:"read_only"`
	CheckedAt     time.Time `json:"checked_at"`
	CheckedBy     string    `json:"checked_by"`
}

// DiscoveredRepo is one repository and the decision about it.
type DiscoveredRepo struct {
	Name          string    `json:"name"`
	Account       string    `json:"account"`
	Affiliation   string    `json:"affiliation"`
	Private       bool      `json:"private"`
	Archived      bool      `json:"archived"`
	Fork          bool      `json:"fork"`
	SizeKB        int       `json:"size_kb"`
	DefaultBranch string    `json:"default_branch"`
	Language      string    `json:"language,omitempty"`
	Included      bool      `json:"included"`
	Reason        string    `json:"reason,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	DiscoveredAt  time.Time `json:"discovered_at"`
}

// ExcludedRepo is a person's decision to leave a repository out.
type ExcludedRepo struct {
	Name       string    `json:"name"`
	Reason     string    `json:"reason"`
	ExcludedBy string    `json:"excluded_by"`
	ExcludedAt time.Time `json:"excluded_at"`
}

// DiscoverySummary counts the latest discovery.
type DiscoverySummary struct {
	Seen     int            `json:"seen"`
	Included int            `json:"included"`
	Skipped  map[string]int `json:"skipped"`
	// LastDiscoveredAt is absent when discovery has never run.
	LastDiscoveredAt *time.Time `json:"last_discovered_at,omitempty"`
}

func (s *Server) handleGitHub(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := s.cfg.Store

	conns, err := st.GitHubConnections(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	found, err := st.Discovery(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	excl, err := st.Exclusions(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	now := s.now()
	out := GitHubView{
		Connections: []GitHubAccount{}, Discovered: []DiscoveredRepo{}, Exclusions: []ExcludedRepo{},
		Summary: DiscoverySummary{Skipped: map[string]int{}},
	}
	for _, c := range conns {
		a := GitHubAccount{
			Account: c.Account, Kind: c.Kind, Scopes: emptyIfNil(c.Scopes), ExpiresAt: c.ExpiresAt,
			ReadOnly: c.ReadOnly, CheckedAt: c.CheckedAt, CheckedBy: c.CheckedBy,
		}
		if c.ExpiresAt != nil {
			days := int(c.ExpiresAt.Sub(now).Hours() / 24)
			if c.ExpiresAt.Before(now) && days == 0 {
				days = -1
			}
			a.ExpiresInDays = &days
		}
		out.Connections = append(out.Connections, a)
	}
	for _, d := range found {
		out.Discovered = append(out.Discovered, DiscoveredRepo{
			Name: d.Name, Account: d.Account, Affiliation: d.Affiliation, Private: d.Private,
			Archived: d.Archived, Fork: d.Fork, SizeKB: d.SizeKB, DefaultBranch: d.DefaultBranch,
			Language: d.Language, Included: d.Included, Reason: d.Reason, Detail: d.Detail,
			DiscoveredAt: d.DiscoveredAt,
		})
		out.Summary.Seen++
		if d.Included {
			out.Summary.Included++
		} else {
			out.Summary.Skipped[d.Reason]++
		}
		if t := d.DiscoveredAt; out.Summary.LastDiscoveredAt == nil || t.After(*out.Summary.LastDiscoveredAt) {
			out.Summary.LastDiscoveredAt = &t
		}
	}
	for _, e := range excl {
		out.Exclusions = append(out.Exclusions, ExcludedRepo{
			Name: e.Name, Reason: e.Reason, ExcludedBy: e.ExcludedBy, ExcludedAt: e.ExcludedAt,
		})
	}
	s.write(w, r, http.StatusOK, out)
}
