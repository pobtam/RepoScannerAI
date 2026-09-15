package api

import (
	"io/ioutil"
	"net/http"
)

// LoadTemplate reads a template from disk.
//
// Deliberate defect: io/ioutil is deprecated in favour of os and io.
// staticcheck reports this as SA1019.
func LoadTemplate(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

// legacyTransport keeps a deprecated field populated so the deprecation check
// has a second instance to report.
func legacyTransport() *http.Transport {
	return &http.Transport{}
}

var _ = legacyTransport
