package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Principal is who is asking.
//
// It reuses the report package's privilege model rather than inventing a
// second one, so the rule governing who may see a secret finding is the same
// rule in a delivered report and in the interface. Two models would diverge,
// and the divergence would be a disclosure.
type Principal struct {
	Recipient report.Recipient
	// Repos are the repositories this caller owns, for the engineer level.
	Repos []string
}

// Determined reports whether the privilege level was established.
//
// Explicit, because "we could not find out" must not be confusable with
// "public": an identity lookup failure that produced the zero value would
// grant the least-privileged view to someone who should have none, and that is
// the failure that goes unnoticed.
func (p Principal) Determined() bool { return p.Recipient.Determined && p.Recipient.Level.Valid() }

// Level is the privilege level.
func (p Principal) Level() report.Level { return p.Recipient.Level }

// MaySeeSecretDetail reports whether this caller may open a secret finding's
// record (VM-UI-F-803).
//
// The security owner group, and the owning repository's code owners. Everyone
// else counts it and cannot open it — which is why the response marks the
// record restricted rather than omitting it: an aggregate that silently
// excluded records the reader cannot open would show four in the rollup and
// three in the list, with no explanation (VM-UI-F-804).
func (p Principal) MaySeeSecretDetail(repo string) bool {
	if p.Recipient.Level >= report.LevelSecurityOwner {
		return true
	}
	if p.Recipient.Level < report.LevelEngineer {
		return false
	}
	for _, r := range p.Repos {
		if r == repo {
			return true
		}
	}
	return false
}

// MaySeeFindingDetail reports whether this caller may open a finding at all.
func (p Principal) MaySeeFindingDetail(f model.Finding) bool {
	if f.Category == model.CategorySecret {
		return p.MaySeeSecretDetail(f.Repo)
	}
	return p.Recipient.Level >= report.LevelEngineer
}

// Authenticator establishes the principal for a request.
//
// An interface because the real one is the organisation identity provider,
// which the framework must build and test without. Every implementation must
// FAIL CLOSED: an undetermined principal is refused, never defaulted.
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}

// HeaderAuth reads the principal from trusted headers set by an authenticating
// proxy.
//
// This is the shape a real deployment takes: the identity provider terminates
// at the ingress and the application trusts the headers it injects. It is
// therefore only safe where those headers CANNOT be set by a client, which is
// a deployment property this code cannot check — so it is named for what it
// trusts, and FINAL-STATUS records it as a human step.
type HeaderAuth struct {
	// UserHeader and LevelHeader name the headers the proxy sets.
	UserHeader  string
	LevelHeader string
	// ReposHeader is a comma-separated list of repositories the caller owns.
	ReposHeader string
}

// Authenticate reads and validates the injected headers.
func (h HeaderAuth) Authenticate(r *http.Request) (Principal, error) {
	user := r.Header.Get(h.UserHeader)
	if user == "" {
		return Principal{}, fmt.Errorf("no %s header; this server expects an authenticating proxy "+
			"to establish identity and will not serve an anonymous request", h.UserHeader)
	}
	raw := r.Header.Get(h.LevelHeader)
	level, ok := report.ParseLevel(raw)
	if !ok {
		// Undetermined, not public. The distinction is the point.
		return Principal{Recipient: report.Undetermined(user)}, nil
	}
	return Principal{
		Recipient: report.Recipient{ID: user, Level: level, Determined: true},
		Repos:     splitList(r.Header.Get(h.ReposHeader)),
	}, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DemoAuth grants one fixed identity, for the local demonstration.
//
// It exists so the demo needs no identity provider and no credentials. It is
// NOT an authentication mode: it grants the same principal to every request,
// which is safe only because the demo binds to localhost and serves seeded
// data. The server reports Demo in /v1/health so the interface can say which
// it is talking to, and FINAL-STATUS lists real authentication as a human
// step.
type DemoAuth struct {
	Level report.Level
	Repos []string
}

// Authenticate returns the fixed demonstration principal.
func (d DemoAuth) Authenticate(_ *http.Request) (Principal, error) {
	level := d.Level
	if !level.Valid() {
		level = report.LevelSecurityOwner
	}
	return Principal{
		Recipient: report.Recipient{ID: "demo-user", Level: level, Determined: true},
		Repos:     d.Repos,
	}, nil
}

// restrict removes the detail a caller may not see, leaving the record
// present.
//
// Present-but-restricted rather than absent, so counts stay consistent with
// lists (VM-UI-F-804). What is withheld is the narrative, the location and the
// identifiers — never a credential value, because no field holds one.
func restrict(f Finding) Finding {
	f.Restricted = true
	f.Identity = Identity{}
	f.Location = Location{}
	f.Triage = nil
	f.Description, f.DescriptionSource = "", ""
	f.Annotations = nil
	f.Refs = Refs{}
	f.Score = nil
	return f
}

var _ = store.ScopeAll
