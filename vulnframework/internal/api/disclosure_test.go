package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// VM-UI-F-105 — no secret VALUE crosses this boundary, on any endpoint, in any
// field.
//
// Three layers, tested separately because each can fail on its own:
//
//  1. STRUCTURE. No response type has a field capable of holding credential
//     material. A secret finding carries its detector, its file and its
//     credential class.
//  2. THE GUARD. Every response is scanned before it is sent, and a response
//     containing credential material is REFUSED rather than logged and sent.
//     This is the layer that catches material arriving through a free-text
//     field — a triage narrative that quoted the matched line.
//  3. THE WALK. Every endpoint is requested and every byte of every response
//     checked against the seeded credential. A new endpoint added without a
//     thought about disclosure fails this test rather than shipping.

// everyEndpoint is the full surface, with arguments filled in.
func everyEndpoint(h *harness) []string {
	return []string{
		"/v1/health",
		"/v1/schema/openapi.json",
		"/v1/runs",
		"/v1/runs/latest",
		"/v1/runs/" + h.RunID,
		"/v1/runs/" + h.RunID + "/snapshot",
		"/v1/findings?scope=all&limit=500",
		"/v1/findings?scope=open&limit=500",
		"/v1/findings?scope=all&category=secret&limit=500",
		"/v1/findings?scope=all&q=" + "aws",
		"/v1/findings/facets?scope=all",
		"/v1/findings/" + h.SecretFP,
		"/v1/findings/" + h.SecretFP + "/timeline",
		"/v1/findings/" + h.SecretFP + "/attempts",
		"/v1/findings/" + h.DepFP,
		"/v1/findings/" + h.DepFP + "/timeline",
		"/v1/findings/" + h.DepFP + "/attempts",
		"/v1/repos",
		"/v1/repos/org/api",
		"/v1/repos/org/api/trend",
		"/v1/coverage",
		"/v1/waves",
		"/v1/metrics/trends?metric=open",
		"/v1/reports",
	}
}

func TestNoEndpointEverReturnsCredentialMaterial(t *testing.T) {
	h := newHarness(t)

	// The credential is planted where one could realistically arrive: the
	// triage narrative for the secret finding, as though the model had quoted
	// the matched line. Nothing in the finding SCHEMA can hold a value, so a
	// free-text field is the only way to test the guard at all — and it is
	// also the way a real leak would happen.
	ctx := context.Background()
	if err := h.Store.SetTriage(ctx, h.SecretFP, model.Triage{
		Description: "the file contains a live AWS key: " + theCredential,
		Impact:      "full access to the staging account",
		Remediation: "rotate the key and remove it from the file",
		TriagedAt:   &apiNow,
		Model:       "claude-sonnet-5",
	}); err != nil {
		t.Fatalf("SetTriage: %v", err)
	}

	var refused int
	for _, path := range everyEndpoint(h) {
		status, body := h.get(t, path)
		if bytes.Contains(body, []byte(theCredential)) {
			t.Fatalf("GET %s returned the credential in its body (status %d). This is the "+
				"disclosure VM-UI-F-105 forbids:\n%s", path, status, truncate(body, 2000))
		}
		if status == http.StatusInternalServerError && bytes.Contains(body, []byte("withheld")) {
			// The guard fired: the response WOULD have contained the
			// credential and was refused. That is the designed behaviour.
			refused++
		}
	}
	if refused == 0 {
		t.Error("no endpoint refused a response despite a credential in a triage narrative. " +
			"Either the narrative is not reaching any response — in which case this test proves " +
			"nothing — or the guard is not running")
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// TestASecretFindingCarriesItsClassAndNeverItsValue is the structural layer.
func TestASecretFindingCarriesItsClassAndNeverItsValue(t *testing.T) {
	h := newHarness(t)

	var f map[string]any
	h.getJSON(t, "/v1/findings/"+h.SecretFP, &f)

	if got := f["credential_type"]; got != "aws_access_key" {
		t.Errorf("credential_type = %v, want the CLASS of credential: without it a reader cannot "+
			"tell what to rotate", got)
	}
	// Every string in the response, checked against the shared definition of
	// "looks like a credential" — the same patterns the report and ticket
	// boundaries use, so all three agree about what a secret is.
	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := model.AssertNoCredential("api-response", encoded); err != nil {
		t.Errorf("the finding response contains credential material: %v", err)
	}
	for _, forbidden := range []string{"value", "secret", "credential_value", "match", "raw"} {
		if _, ok := f[forbidden]; ok {
			t.Errorf("the response carries a %q field. A secret finding's record has nowhere to "+
				"put the credential, and neither should its rendering (VM-F-263)", forbidden)
		}
	}
}

// TestTheGuardRefusesRatherThanScrubbing is the negative that matters: a
// response that quietly dropped the offending field would look correct and
// would leave the producer's defect in place for the next boundary to leak.
func TestTheGuardRefusesRatherThanScrubbing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.Store.SetTriage(ctx, h.DepFP, model.Triage{
		Description: "reachable through the handler; the deploy key is " + theCredential,
		TriagedAt:   &apiNow,
	}); err != nil {
		t.Fatalf("SetTriage: %v", err)
	}

	status, body := h.get(t, "/v1/findings/"+h.DepFP)
	if status == http.StatusOK {
		t.Fatalf("a response containing credential material was sent with 200. Scrubbing the "+
			"field silently would be worse than refusing: the producer's defect stays in place "+
			"and the next boundary leaks it.\n%s", truncate(body, 800))
	}
	if !bytes.Contains(body, []byte("credential material")) {
		t.Errorf("the refusal does not say why: %s", body)
	}
	if !bytes.Contains(body, []byte("at the producer")) {
		t.Errorf("the refusal does not say where the fix belongs: %s", body)
	}
}

// TestSecretDetailIsRestrictedButStillCounted is VM-UI-F-803 and VM-UI-F-804
// together: the rule that hides the detail must not make the aggregate lie.
func TestSecretDetailIsRestrictedButStillCounted(t *testing.T) {
	h := newHarnessAtLevel(t, report.LevelEngineer, []string{"org/web"})

	// The engineer owns org/web, not org/api, so org/api's secret is
	// restricted to them.
	var page map[string]any
	h.getJSON(t, "/v1/findings?scope=all&category=secret&limit=100", &page)

	matched := int(page["matched"].(float64))
	if matched == 0 {
		t.Fatal("no secret findings matched; the test needs one")
	}
	restricted := int(page["restricted_count"].(float64))
	if restricted == 0 {
		t.Error("an engineer who owns a different repository sees every secret finding in full")
	}
	findings := page["findings"].([]any)
	if len(findings) != matched {
		t.Errorf("the page returned %d of %d matching findings. An aggregate that silently "+
			"excluded what the reader cannot open shows four in the rollup and three in the "+
			"list, with no explanation (VM-UI-F-804)", len(findings), matched)
	}
	var sawRestricted bool
	for _, raw := range findings {
		f := raw.(map[string]any)
		if f["restricted"] == true {
			sawRestricted = true
			if id, ok := f["identity"].(map[string]any); ok && id["primary_id"] != nil && id["primary_id"] != "" {
				t.Errorf("a restricted finding still carries its identity: %v", id)
			}
			if f["fingerprint"] == "" {
				t.Error("a restricted finding carries no fingerprint, so it cannot be counted or " +
					"referred to")
			}
		}
	}
	if !sawRestricted {
		t.Error("no finding was marked restricted, so the reader cannot tell why they see less")
	}

	// And the detail endpoint refuses, saying so rather than pretending the
	// record does not exist.
	status, body := h.get(t, "/v1/findings/"+h.SecretFP)
	if status != http.StatusForbidden {
		t.Errorf("GET a restricted finding = %d, want 403: telling the reader it does not exist "+
			"would be a lie they cannot act on\n%s", status, truncate(body, 400))
	}
	if !strings.Contains(string(body), "security owner") {
		t.Errorf("the refusal does not say who can see it: %s", body)
	}
}

// newHarnessAtLevel builds a server whose principal is less privileged.
func newHarnessAtLevel(t *testing.T, level report.Level, repos []string) *harness {
	t.Helper()
	h := newHarness(t)
	// Rebuild the server over the same store with a different principal.
	replaceAuth(t, h, level, repos)
	return h
}

var _ = store.ScopeAll
var _ = fmt.Sprintf
