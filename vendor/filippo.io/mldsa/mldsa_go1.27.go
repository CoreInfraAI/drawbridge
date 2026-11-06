// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !fips140v1.0

// Package mldsa implements the post-quantum ML-DSA signature scheme specified
// in [FIPS 204].
//
// It is a wrapper around the standard library's [crypto/mldsa] package.
// It uses type aliases, so this package and the standard library's can be used
// interchangeably even within the same program.
//
// [FIPS 204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
package mldsa

import "crypto/mldsa"

const (
	PrivateKeySize = mldsa.PrivateKeySize

	MLDSA44PublicKeySize = mldsa.MLDSA44PublicKeySize
	MLDSA65PublicKeySize = mldsa.MLDSA65PublicKeySize
	MLDSA87PublicKeySize = mldsa.MLDSA87PublicKeySize

	MLDSA44SignatureSize = mldsa.MLDSA44SignatureSize
	MLDSA65SignatureSize = mldsa.MLDSA65SignatureSize
	MLDSA87SignatureSize = mldsa.MLDSA87SignatureSize
)

type Parameters = mldsa.Parameters
type Options = mldsa.Options
type PrivateKey = mldsa.PrivateKey
type PublicKey = mldsa.PublicKey

// MLDSA44 returns [mldsa.MLDSA44].
func MLDSA44() Parameters { return mldsa.MLDSA44() }

// MLDSA65 returns [mldsa.MLDSA65].
func MLDSA65() Parameters { return mldsa.MLDSA65() }

// MLDSA87 returns [mldsa.MLDSA87].
func MLDSA87() Parameters { return mldsa.MLDSA87() }

// GenerateKey calls [mldsa.GenerateKey].
func GenerateKey(params Parameters) (*PrivateKey, error) {
	return mldsa.GenerateKey(params)
}

// NewPrivateKey calls [mldsa.NewPrivateKey].
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	return mldsa.NewPrivateKey(params, seed)
}

// NewPublicKey calls [mldsa.NewPublicKey].
func NewPublicKey(params Parameters, encoding []byte) (*PublicKey, error) {
	return mldsa.NewPublicKey(params, encoding)
}

// Verify calls [mldsa.Verify].
func Verify(pk *PublicKey, message []byte, signature []byte, opts *Options) error {
	return mldsa.Verify(pk, message, signature, opts)
}
