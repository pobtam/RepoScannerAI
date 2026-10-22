package store_test

import (
	"context"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/testkeys"
)

// The scanner's description survives into the stored finding on both
// backends. Where two tools describe one finding, the first in tool order
// wins, so the text does not depend on which finished first; and a
// description quoting something credential-shaped is never stored.
func TestFindingCarriesTheScannersDescription(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		osv := cryptoFinding("osv-scanner")
		osv.Description = "Potential denial of service in golang.org/x/crypto"
		gvc := cryptoFinding("govulncheck")
		gvc.Description = "Potential denial of service in   golang.org/x/crypto/ssh"

		// osv-scanner first: the merged text must still be govulncheck's.
		r1 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{osv}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{gvc}); err != nil {
			t.Fatal(err)
		}
		f, err := s.GetFinding(ctx, cryptoFP())
		if err != nil {
			t.Fatal(err)
		}
		if want := "Potential denial of service in golang.org/x/crypto/ssh"; f.Description != want {
			t.Errorf("description = %q, want govulncheck's, whitespace collapsed: %q", f.Description, want)
		}

		// Seen again with a description that quotes a key: not stored, and
		// govulncheck's newer observation now supplies nothing, so osv's text
		// is used.
		leaky := cryptoFinding("govulncheck")
		leaky.Description = "token " + testkeys.AWSAccessKeyID() + " in the handshake"
		r2 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r2.ID, testRepo, []model.RawFinding{leaky}); err != nil {
			t.Fatal(err)
		}
		f, _ = s.GetFinding(ctx, cryptoFP())
		if f.Description != osv.Description {
			t.Errorf("after a credential-quoting description: %q, want osv-scanner's %q", f.Description, osv.Description)
		}
	})
}
