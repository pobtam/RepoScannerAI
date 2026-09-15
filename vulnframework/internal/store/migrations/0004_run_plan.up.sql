-- 0004_run_plan: planned scope, so coverage is measured against what was
-- intended rather than against what happened to run (OQ-P2-02).
--
-- Without this table an in-scope repository that is never dispatched is simply
-- absent from the run, and absence reads as clean. The planner records what it
-- intended to scan; run close writes the planned-minus-produced delta as
-- explicit gap rows.

CREATE TABLE run_plan (
  run_id        TEXT NOT NULL REFERENCES runs(id),
  repo          TEXT NOT NULL REFERENCES repos(name),
  -- planned    — in scope, not yet dispatched
  -- dispatched — a worker was started for it
  -- skipped    — deliberately not dispatched; skip_reason says why
  dispatch_state TEXT NOT NULL
                 CHECK (dispatch_state IN ('planned','dispatched','skipped')),
  skip_reason    TEXT,
  planned_at     TIMESTAMPTZ NOT NULL,
  dispatched_at  TIMESTAMPTZ,
  PRIMARY KEY (run_id, repo)
);
CREATE INDEX run_plan_run_idx ON run_plan (run_id, dispatch_state);

-- Two further outcomes, kept distinct rather than folded into 'failed'.
--
--   not_dispatched — the scan never started. Either the planner deliberately
--                    skipped it (budget, quota, filter — skip_reason says
--                    which) or it was never picked up at all.
--   no_result      — a worker WAS dispatched and produced nothing. The scan
--                    started and the result was lost.
--
-- The distinction decides who is asked to fix it and what the fix is: raise a
-- budget, versus find out why a worker died. Overloading 'failed' would merge
-- three different operational problems into one number.
ALTER TABLE repo_scan_results DROP CONSTRAINT repo_scan_results_outcome_check;
ALTER TABLE repo_scan_results ADD CONSTRAINT repo_scan_results_outcome_check
  CHECK (outcome IN ('complete','partial','failed','not_dispatched','no_result'));
