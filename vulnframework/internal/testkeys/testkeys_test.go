package testkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Each value must still look like the credential it stands for, or the
// tests that plant it prove nothing about detection. The patterns are the
// shapes secret scanners and GitHub push protection match.
func TestValuesHaveTheirCredentialShape(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		pattern string
	}{
		{"aws access key id", AWSAccessKeyID(), `^AKIA[0-9A-Z]{16}$`},
		{"aws example key id", AWSExampleKeyID(), `^AKIA[0-9A-Z]{16}$`},
		{"aws secret access key", AWSSecretAccessKey(), `^[A-Za-z0-9/+=]{40}$`},
		{"github pat", GitHubPAT(), `^ghp_[A-Za-z0-9]{36,}$`},
		{"github pat zeros", GitHubPATZeros(), `^ghp_0{36}$`},
		{"gitlab pat", GitLabPAT(), `^glpat-[A-Za-z0-9_-]{20,}$`},
		{"slack bot token", SlackBotToken(), `^xoxb-[0-9]{10,13}-[a-zA-Z0-9-]*$`},
		{"private key header", PrivateKeyHeader(), `^-----BEGIN RSA PRIVATE KEY-----$`},
	}
	for _, c := range cases {
		if !regexp.MustCompile(c.pattern).MatchString(c.value) {
			t.Errorf("%s = %q, which no longer matches %s", c.name, c.value, c.pattern)
		}
	}
}

func TestExpandAndConcealAreInverse(t *testing.T) {
	var b strings.Builder
	for _, n := range Names() {
		b.WriteString("key: " + Placeholder(n) + "\n")
	}
	committed := b.String()

	expanded := string(Expand([]byte(committed)))
	if strings.Contains(expanded, "@@TESTKEY:") {
		t.Fatalf("Expand left a placeholder:\n%s", expanded)
	}
	for _, n := range Names() {
		v, _ := Value(n)
		if !strings.Contains(expanded, v) {
			t.Errorf("Expand did not substitute %s", n)
		}
	}
	if got := string(Conceal([]byte(expanded))); got != committed {
		t.Errorf("Conceal(Expand(x)) != x:\n%s", got)
	}
}

// The package exists so that tests can plant credentials. A deployed program
// that imported it would carry them.
func TestNoProgramImportsTestkeys(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(line, "/internal/testkeys") {
			t.Fatalf("a program under cmd/ imports internal/testkeys")
		}
	}
}
