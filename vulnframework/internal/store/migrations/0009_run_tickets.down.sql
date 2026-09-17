ALTER TABLE remediation_prs DROP COLUMN IF EXISTS merged;
ALTER TABLE remediation_prs DROP COLUMN IF EXISTS ticket_url;
ALTER TABLE remediation_prs DROP COLUMN IF EXISTS ticket_ref;
DROP TABLE IF EXISTS run_tickets;
