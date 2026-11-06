//go:build go1.27 && !fips140v1.0

package fips140

import "crypto/fips140"

// Enabled reports whether crypto/mldsa, which filippo.io/mldsa wraps in this
// configuration, is operating in FIPS 140-3 mode.
func Enabled() bool { return fips140.Enabled() }
