// Package audit holds the Producer-Coverage Audit.
//
// It exists because one defect recurred three times in a single phase, and it
// is the dominant risk mode of this architecture rather than an incident:
//
//	a schema field that a consumer READS and that no real producer WRITES.
//
// `FirstPartyPath` (Phase 6): the store projection dropped it, so upstream
// defer could never fire. `ImportPath` (Phase 11): no adapter populated it, so
// classification always found nothing. `module_deps` (Phase 11): the schema
// had held the table since migration 0001 and nothing ever wrote a row.
//
// All three were invisible to a fully green suite, and for the same reason:
// every test that exercised the consumer SUPPLIED the field itself. A test
// that constructs the finding it tests cannot discover that nothing constructs
// it in production. The defect is not in any component — each worked — it is
// in the join between two of them, and joins are what unit tests are worst at
// seeing.
//
// So this audit inverts the question. Instead of asking "does the consumer
// handle this field", it asks "does any real producer ever set it", and it
// answers by RUNNING the producers — the captured scanner fixtures through the
// real adapters, a real go.mod through the real manifest reader, real webhook
// bodies through the real verifier — and recording which fields come out
// populated.
//
// A field nobody writes must then be either fixed or explicitly exempted with
// the name of whatever does write it. An exemption is not a way to dismiss a
// gap: it is a claim about a producer, and the claim is checkable.
package audit
