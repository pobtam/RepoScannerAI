package model

import (
	"strings"
	"testing"
)

// A key-shaped value, assembled at run time so no file holds one. (The model
// may not import internal/testkeys; this is the same AWS-shaped fake.)
func fakeAWSKeyID() string { return "AK" + "IA" + "4RQ7T2XZ" + "KPLMWDV3" }

func TestSafeDescription(t *testing.T) {
	if got := SafeDescription("  Potential\n\tfile   inclusion \n"); got != "Potential file inclusion" {
		t.Errorf("whitespace: %q", got)
	}
	long := strings.Repeat("word ", 1000)
	if got := []rune(SafeDescription(long)); len(got) != MaxDescriptionRunes || got[len(got)-1] != '…' {
		t.Errorf("a long description is %d runes ending %q; want %d ending with an ellipsis", len(got), string(got[len(got)-1]), MaxDescriptionRunes)
	}
	// A semgrep message can quote the matched line. A description holding
	// something credential-shaped is dropped, not partly kept.
	quoted := "Hard-coded AWS key " + fakeAWSKeyID() + " found in the client constructor"
	if got := SafeDescription(quoted); got != "" {
		t.Errorf("a description quoting a key was kept: %q", got)
	}
}

func TestEveryFindingHasADescription(t *testing.T) {
	str := func(s string) *string { return &s }
	line := 42
	cases := []struct {
		name       string
		f          Finding
		wantSource string
		want       []string
	}{
		{
			name:       "the scanner's own text, credited to the tools that reported it",
			f:          Finding{Description: "Potential file inclusion via variable", Provenance: Provenance{Tools: []string{"gosec", "semgrep"}}},
			wantSource: "gosec, semgrep",
			want:       []string{"Potential file inclusion via variable"},
		},
		{
			name: "dependency without scanner text",
			f: Finding{Category: CategoryDependency, Identity: Identity{PrimaryID: "GO-2025-3106"},
				Location: Location{Module: "golang.org/x/crypto"}, Versions: Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
				Classification: Classification{Reachable: ReachableTrue}},
			wantSource: DescriptionSourceDerived,
			want:       []string{"golang.org/x/crypto v0.35.0 is affected by GO-2025-3106", "v0.36.0", "is called from this repository"},
		},
		{
			name:       "dependency with no fix published",
			f:          Finding{Category: CategoryDependency, Identity: Identity{PrimaryID: "GHSA-x"}, Location: Location{Module: "left-pad"}},
			wantSource: DescriptionSourceDerived,
			want:       []string{"left-pad is affected by GHSA-x", "No fixed version is recorded"},
		},
		{
			name:       "secret, by class and file only",
			f:          Finding{Category: CategorySecret, CredentialType: "aws-access-token", Location: Location{File: str("config/settings.yaml")}},
			wantSource: DescriptionSourceDerived,
			want:       []string{"aws-access-token", "config/settings.yaml", "rotate it first"},
		},
		{
			name: "code",
			f: Finding{Category: CategoryCode, Identity: Identity{RuleID: str("G304")}, Location: Location{File: str("main.go"), Line: &line},
				Provenance: Provenance{Tools: []string{"gosec"}}},
			wantSource: DescriptionSourceDerived,
			want:       []string{"Rule G304 from gosec", "main.go:42"},
		},
		{
			name:       "config",
			f:          Finding{Category: CategoryConfig, Identity: Identity{RuleID: str("DS002")}, Location: Location{File: str("Dockerfile")}, Provenance: Provenance{Tools: []string{"trivy"}}},
			wantSource: DescriptionSourceDerived,
			want:       []string{"Configuration check DS002 failed in Dockerfile", "trivy"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, source := Describe(tc.f)
			if source != tc.wantSource {
				t.Errorf("source = %q, want %q", source, tc.wantSource)
			}
			for _, w := range tc.want {
				if !strings.Contains(text, w) {
					t.Errorf("description %q lacks %q", text, w)
				}
			}
		})
	}
}
