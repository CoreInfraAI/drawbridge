//go:build !go1.27 || fips140v1.0

package fips140

// Enabled returns false, as the standalone implementation used in this
// configuration never operates in FIPS 140-3 mode.
func Enabled() bool { return false }
