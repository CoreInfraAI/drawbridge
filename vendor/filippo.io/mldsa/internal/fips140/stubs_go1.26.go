//go:build go1.26

package fips140

import "crypto/fips140"

func Version() string { return fips140.Version() }
