//go:build !go1.26

package fips140

// Older versions of Go than 1.26 only provide FIPS 140-3 module v1.0.0, if any.

func Version() string { return "v1.0.0" }
