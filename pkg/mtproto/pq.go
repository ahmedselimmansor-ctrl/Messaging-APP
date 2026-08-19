package mtproto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// The pq step is MTProto's proof of work against connection floods.
//
// Before the server spends a 2048-bit modular exponentiation on a stranger,
// it hands them a semiprime and demands its factors. Factoring a 63-bit
// semiprime costs a client a few milliseconds; producing one costs the server
// almost nothing. An attacker who wants to make the server do the expensive
// DH work must therefore pay first, and pay per connection.
//
// It is a speed bump, not a defence in depth: it raises the cost of a flood
// by orders of magnitude but does not replace Cloud Armor at the edge or the
// per-IP handshake rate limit in front of it.

// ErrNotFactors is returned when a client's claimed factors are wrong.
var ErrNotFactors = errors.New("mtproto: p*q does not equal pq, or the factors are trivial")

// GeneratePQ returns a semiprime pq together with its factors p < q.
//
// Each factor is around 31 bits, so pq lands just under 2^62 and always fits
// an int64 with room to spare.
func GeneratePQ() (pq, p, q uint64, err error) {
	for attempts := 0; attempts < 64; attempts++ {
		p, err = randomPrime31()
		if err != nil {
			return 0, 0, 0, err
		}
		q, err = randomPrime31()
		if err != nil {
			return 0, 0, 0, err
		}
		if p == q {
			continue
		}
		if p > q {
			p, q = q, p
		}
		return p * q, p, q, nil
	}
	return 0, 0, 0, errors.New("mtproto: could not generate a semiprime")
}

// randomPrime31 returns a prime in [2^30, 2^31).
func randomPrime31() (uint64, error) {
	for {
		n, err := rand.Prime(rand.Reader, 31)
		if err != nil {
			return 0, fmt.Errorf("mtproto: generate prime: %w", err)
		}
		v := n.Uint64()
		if v >= 1<<30 {
			return v, nil
		}
	}
}

// VerifyPQ checks a client's claimed factorisation.
func VerifyPQ(pq, p, q uint64) error {
	if p <= 1 || q <= 1 || p == pq || q == pq {
		return ErrNotFactors
	}
	if p*q != pq {
		return ErrNotFactors
	}
	return nil
}

// FactorPQ splits a semiprime using Brent's variant of Pollard's rho.
//
// This is the client's side of the proof of work. It also runs in the test
// suite and in the load generator, which is why it lives in the shared
// package rather than in a client-only one.
func FactorPQ(pq uint64) (p, q uint64, err error) {
	if pq < 4 {
		return 0, 0, fmt.Errorf("mtproto: %d is too small to factor", pq)
	}
	if pq%2 == 0 {
		return 2, pq / 2, nil
	}

	n := new(big.Int).SetUint64(pq)
	for c := uint64(1); c < 64; c++ {
		if f := brent(n, c); f != nil && f.Uint64() != 1 && f.Uint64() != pq {
			a := f.Uint64()
			b := pq / a
			if a > b {
				a, b = b, a
			}
			return a, b, nil
		}
	}
	return 0, 0, fmt.Errorf("mtproto: failed to factor %d", pq)
}

// brent runs one round of Brent's cycle-finding factorisation.
//
// It is written on big.Int rather than uint64 because x*x + c overflows 64
// bits for factors of this size, and a wrong answer here is worse than a slow
// one.
func brent(n *big.Int, c uint64) *big.Int {
	one := big.NewInt(1)
	cBig := new(big.Int).SetUint64(c)

	f := func(x *big.Int) *big.Int {
		r := new(big.Int).Mul(x, x)
		r.Add(r, cBig)
		return r.Mod(r, n)
	}

	x := big.NewInt(2)
	y := big.NewInt(2)
	d := big.NewInt(1)
	tmp := new(big.Int)

	// Bound the work: a legitimate 62-bit semiprime falls out well inside
	// this, and an adversarial input cannot pin a CPU indefinitely.
	const maxSteps = 1 << 22

	for step := 0; step < maxSteps; step++ {
		x = f(x)
		y = f(f(y))

		tmp.Sub(x, y)
		tmp.Abs(tmp)
		if tmp.Sign() == 0 {
			return nil // cycle without a factor; caller retries with a new c
		}
		d.GCD(nil, nil, tmp, n)
		if d.Cmp(one) > 0 {
			if d.Cmp(n) == 0 {
				return nil
			}
			return d
		}
	}
	return nil
}
