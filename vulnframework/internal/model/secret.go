package model

import (
	"fmt"
	"regexp"
)

// CredentialPatterns match tokens that look like live credentials.
//
// This is the shared definition of "looks like a secret", and it lives in the
// model because more than one boundary has to enforce the same rule: the report
// that leaves the system (VM-F-263), the ticket that carries the finding into
// somebody's inbox (VM-F-703), and the durable queue that holds an operation
// between attempts. Two definitions would mean two boundaries disagreeing about
// what a credential is, and the weaker one decides.
//
// The patterns scan RENDERED TEXT, not the model. The finding record already
// has nowhere to put a credential and the gitleaks adapter redacts at
// normalisation; this catches material arriving through any other field — a
// triage narrative that quoted the matched line, a path containing a token,
// text a caller composed by hand.
var CredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                                 // AWS access key id
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),                                                 // AWS temporary key id
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                       // GitHub tokens
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),                                        // GitLab PAT
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),                                     // Slack
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`),                                              // generic API secret keys
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),                                   // private keys
	regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), // JWT
}

// ErrCredential reports that an artifact contains something shaped like a live
// credential.
//
// The operation fails rather than scrubbing silently. Something that cannot be
// made safe should not be sent, and a silent scrub would hide the fact that
// credential material reached the boundary at all — which is the defect worth
// knowing about.
type ErrCredential struct {
	Artifact string
	Pattern  string
}

func (e *ErrCredential) Error() string {
	return fmt.Sprintf(
		"refusing to emit %s: it contains something matching %s. "+
			"A secret's value must never leave the system, in any field (VM-F-263, VM-UI-F-105). "+
			"Find how credential material reached this boundary rather than scrubbing it here",
		e.Artifact, e.Pattern)
}

// AssertNoCredential scans rendered bytes for credential material.
func AssertNoCredential(artifact string, body []byte) error {
	for _, re := range CredentialPatterns {
		if re.Find(body) != nil {
			return &ErrCredential{Artifact: artifact, Pattern: re.String()}
		}
	}
	return nil
}
