-- The upstream finding a blocked consumer is waiting on (VM-F-604).
--
-- A column rather than a field in the finding document: the document is
-- rebuilt from observations on every scan, so a reference kept inside it
-- would be erased by the next run -- the same reason the ticket and pull
-- request references live outside it.
ALTER TABLE findings ADD COLUMN upstream_finding TEXT;
