// Package testkeys holds the fabricated credentials tests plant and then
// prove are detected, redacted or refused.
//
// No complete key-like string is written in any file of this repository:
// GitHub push protection, and every secret scanner, reads files, not
// programs. Each value here is joined from parts at run time, so the source
// never matches a credential pattern while the running test still sees a
// value that does. None of them belongs to a real account.
//
// Fixture files on disk (recorded tool output, the synthetic repositories
// the scanner image is pointed at) carry placeholders instead, written
// @@TESTKEY:name@@, and Expand substitutes the values when a test reads them
// or when testdata/capture.sh copies the repositories into the image.
//
// Only tests may import this package; TestNoProgramImportsTestkeys enforces
// that.
package testkeys

import (
	"bytes"
	"sort"
	"strings"
)

func join(parts ...string) string { return strings.Join(parts, "") }

// AWSAccessKeyID is the fabricated AWS access key ID planted in the go-api
// synthetic repository. It is deliberately not AWS's documentation example,
// which gitleaks allowlists.
func AWSAccessKeyID() string { return join("AK", "IA", "4RQ7T2XZ", "KPLMWDV3") }

// AWSSecretAccessKey is the fabricated secret paired with AWSAccessKeyID.
func AWSSecretAccessKey() string {
	return join("wJ2f9Kq1", "Lx0PbN7s", "TvUe4RcY", "gHmZa6Di", "QoXpB3Er")
}

// AWSExampleKeyID is AWS's documented example access key ID. Scanners
// allowlist it, so tests use it where a value must look like a key to a
// redaction filter but must not be reported by gitleaks.
func AWSExampleKeyID() string { return join("AK", "IA", "IOSFODNN", "7EXAMPLE") }

// GitHubPAT is a fabricated classic GitHub personal access token.
func GitHubPAT() string {
	return join("gh", "p_", "ZmFrZXRva2Vu", "Zm9ydGVzdGlu", "ZzEyMzQ1NmFi", "Y2RlZg")
}

// GitHubPATZeros is a GitHub-token-shaped value of zeros, for environment
// variables a runner would have in scope.
func GitHubPATZeros() string { return join("gh", "p_", strings.Repeat("0", 36)) }

// GitLabPAT is a fabricated GitLab personal access token.
func GitLabPAT() string { return join("gl", "pat-", "ZmFrZXRva2Vu", "Zm9ydGVzdA") }

// SlackBotToken is a fabricated Slack bot token.
func SlackBotToken() string { return join("xo", "xb-", "123456789012", "-", "abcdefghijklm") }

// PrivateKeyHeader is the first line of a PEM-encoded RSA private key.
func PrivateKeyHeader() string { return join("-----BEGIN ", "RSA PRIVATE", " KEY-----") }

// placeholders maps each placeholder name to its value.
func placeholders() map[string]string {
	return map[string]string{
		"aws-access-key-id":     AWSAccessKeyID(),
		"aws-secret-access-key": AWSSecretAccessKey(),
		"aws-example-key-id":    AWSExampleKeyID(),
		"github-pat":            GitHubPAT(),
		"gitlab-pat":            GitLabPAT(),
		"slack-bot-token":       SlackBotToken(),
	}
}

// Placeholder returns the placeholder text for name, as written in fixture
// files.
func Placeholder(name string) string { return "@@TESTKEY:" + name + "@@" }

// Names lists every placeholder name, sorted.
func Names() []string {
	var out []string
	for n := range placeholders() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Expand replaces every placeholder in b with its value.
func Expand(b []byte) []byte {
	for name, value := range placeholders() {
		b = bytes.ReplaceAll(b, []byte(Placeholder(name)), []byte(value))
	}
	return b
}

// Conceal is the inverse of Expand: every value becomes its placeholder.
// testdata/capture.sh runs it over freshly captured tool output, which
// echoes the planted values back.
func Conceal(b []byte) []byte {
	for name, value := range placeholders() {
		b = bytes.ReplaceAll(b, []byte(value), []byte(Placeholder(name)))
	}
	return b
}

// Value returns the value for a placeholder name, and whether it exists.
func Value(name string) (string, bool) {
	v, ok := placeholders()[name]
	return v, ok
}
