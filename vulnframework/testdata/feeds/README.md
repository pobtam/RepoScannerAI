# Feed fixtures — and what they are not

These are the sample payloads the KEV and EPSS clients in `internal/feed` are
tested against.

**They were written by hand to match the publishers' documented formats. They
were not captured from the live services.** This build has no network access
by design, so nobody here has seen a real response from either endpoint.

That distinction matters, and it is the reason these do not live under
`testdata/fixtures/`. Everything in that directory is **real captured output**
from a pinned scanner, governed by `config/tools.lock` and by the shape
inventory in `internal/scan/adapters/fixtures_test.go`: a fixture there records
the exact tool build that produced it, so a change in findings is attributable
to the fleet rather than to a silent tool upgrade. A hand-written sample placed
beside those would claim a provenance it does not have.

## What this means for the tests

The client tests prove the client's **logic** — that a feed which is down is
not mistaken for a feed that answered and knew nothing, that a truncated
catalogue is refused, that an unlisted identifier is omitted rather than
zero-filled. Every one of those is a property of the client and is tested
honestly here.

They do **not** prove that the real publications look like this. If CISA or
FIRST emit a field, an encoding or a date format these samples do not contain,
the client will meet it for the first time in production.

## The human step

Before either feed is enabled (D3), capture one real response from each
endpoint, diff it against these samples, and replace them with the captured
ones — at which point they gain a real provenance and should be recorded with
it. `GO-LIVE-CHECKLIST.md` carries this as a precondition rather than leaving
it to be discovered.

## Sources

| File | Publication | Documented format |
|---|---|---|
| `kev.json` | CISA Known Exploited Vulnerabilities catalogue | single JSON document, `count` + `vulnerabilities[]` |
| `epss.csv.gz` | FIRST Exploit Prediction Scoring System daily snapshot | gzipped CSV, `#model_version:…,score_date:…` comment then a `cve,epss,percentile` header |
