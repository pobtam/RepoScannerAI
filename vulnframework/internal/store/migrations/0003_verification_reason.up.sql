-- 0003_verification_reason: record how a finding was verified (VM-AD §6.1.1).
--
-- Disappearance on a qualifying scan is the universal verification trigger, so
-- VERIFIED no longer implies this framework fixed anything. One VERIFIED state
-- is kept and the attribution is recorded alongside it, because a fleet report
-- that cannot tell "we fixed it" from "it went away" is claiming credit it has
-- not earned.
--
--   framework_merge — passed through MERGED: this framework's PR closed it
--   upstream        — closed by a first-party upstream fix
--   external        — disappeared without the framework merging anything

ALTER TABLE findings
  ADD COLUMN verified_reason TEXT
  CHECK (verified_reason IS NULL
         OR verified_reason IN ('framework_merge','upstream','external'));

CREATE INDEX findings_verified_reason_idx ON findings (verified_reason)
  WHERE verified_reason IS NOT NULL;
