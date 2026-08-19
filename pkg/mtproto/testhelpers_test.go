package mtproto

import (
	"math/big"
	"testing"
)

func bigOne() *big.Int { return big.NewInt(1) }

func mustBig(t *testing.T, dec string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		t.Fatalf("not a decimal integer: %q", dec)
	}
	return v
}
