package authn

import "math/big"

// bigFromBytes reads a big-endian unsigned integer, as JWKS coordinates are
// encoded.
func bigFromBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
