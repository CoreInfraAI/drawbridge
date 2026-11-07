// Package mldsacrypto is a stand-in for the standard library's crypto package.
package mldsacrypto

import "crypto"

// MLDSAMu is a function that produces a [pre-hashed μ message representative].
// It has no implementation, but is used a [crypto.SignerOpts.HashFunc] return
// value for [mldsa.PrivateKey.Sign].
//
// [pre-hashed μ message representative]: https://www.rfc-editor.org/rfc/rfc9881.html#externalmu
const MLDSAMu crypto.Hash = 20
