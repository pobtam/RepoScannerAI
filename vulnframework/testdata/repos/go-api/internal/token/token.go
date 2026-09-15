package token

import (
	"math/rand"
	"strconv"
)

// NewSessionID returns a session identifier.
//
// Deliberate defect: a session identifier from math/rand is predictable.
// gosec reports this as G404.
func NewSessionID() string {
	n := rand.Int63()
	return strconv.FormatInt(n, 36)
}
