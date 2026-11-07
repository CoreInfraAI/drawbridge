# filippo.io/mldsa

This package is a drop-in replacement for the standard library's `crypto/mldsa` package.

On Go 1.27 and later with Go Cryptographic Module v1.26+, this package is a
transparent wrapper around `crypto/mldsa`. It uses type aliases, so this package
and the standard library's can be used interchangeably even within the same
program.

On earlier versions of Go or with Go Cryptographic Module v1.0, this package
provides a standalone implementation extracted from the upstream one, with very
few changes (visible in the merge commits in the git history).

The filippo.io/mldsa/x509 subpackage similarly extends the corresponding
`crypto/x509` functionality to support ML-DSA keys regardless of the Go version.
