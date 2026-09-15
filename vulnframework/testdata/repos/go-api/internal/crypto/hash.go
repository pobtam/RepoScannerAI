package crypto

import (
	"crypto/sha1"
	"encoding/hex"
)

// Fingerprint hashes a value.
//
// Deliberate defect: SHA-1 is a weak cryptographic primitive. gosec reports
// this as G401, and staticcheck flags the deprecated usage pattern.
func Fingerprint(in []byte) string {
	h := sha1.New()
	h.Write(in)
	return hex.EncodeToString(h.Sum(nil))
}
