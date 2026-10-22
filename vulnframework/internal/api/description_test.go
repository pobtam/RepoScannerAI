package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/report"
)

// Every finding the interface lists or opens says what the problem is: the
// scanner's own text where one was recorded, credited to the tool, and an
// account built from the record otherwise, marked "derived" so it is never
// mistaken for the tool's words.
func TestEveryFindingHasADescription(t *testing.T) {
	h := newHarness(t)

	var page struct {
		Findings []struct {
			Fingerprint       string `json:"fingerprint"`
			Category          string `json:"category"`
			Description       string `json:"description"`
			DescriptionSource string `json:"description_source"`
		} `json:"findings"`
	}
	h.getJSON(t, "/v1/findings?scope=all&limit=100", &page)
	if len(page.Findings) == 0 {
		t.Fatal("no findings to check")
	}
	var sawTool, sawDerived bool
	for _, f := range page.Findings {
		if f.Description == "" || f.DescriptionSource == "" {
			t.Errorf("%s finding %s: description %q from %q", f.Category, f.Fingerprint, f.Description, f.DescriptionSource)
		}
		switch {
		case f.Category == "code":
			sawTool = true
			if f.Description != "Use of weak cryptographic primitive" || f.DescriptionSource != "gosec" {
				t.Errorf("code finding: %q from %q; want gosec's own text", f.Description, f.DescriptionSource)
			}
		case f.DescriptionSource == "derived":
			sawDerived = true
		}
	}
	if !sawTool || !sawDerived {
		t.Errorf("want both a scanner description and a derived one; tool=%v derived=%v", sawTool, sawDerived)
	}

	var detail struct {
		Description       string `json:"description"`
		DescriptionSource string `json:"description_source"`
	}
	h.getJSON(t, "/v1/findings/"+h.DepFP, &detail)
	if !strings.Contains(detail.Description, "is affected by") || detail.DescriptionSource != "derived" {
		t.Errorf("dependency detail: %q from %q", detail.Description, detail.DescriptionSource)
	}
}

// A finding the caller may count but not open carries no description: it is
// part of the detail that is withheld.
func TestRestrictedFindingsWithholdTheirDescription(t *testing.T) {
	h := newHarnessAtLevel(t, report.LevelEngineer, []string{"org/web"})
	var page struct {
		Findings []map[string]any `json:"findings"`
	}
	h.getJSON(t, "/v1/findings?scope=all&category=secret&limit=100", &page)
	saw := false
	for _, f := range page.Findings {
		if f["restricted"] != true {
			continue
		}
		saw = true
		if _, ok := f["description"]; ok {
			t.Errorf("a restricted finding carries a description: %v", f["description"])
		}
	}
	if !saw {
		t.Fatal("no restricted finding to check")
	}
	if status, _ := h.get(t, "/v1/findings/"+h.SecretFP); status != http.StatusForbidden {
		t.Errorf("restricted detail = %d", status)
	}
}
