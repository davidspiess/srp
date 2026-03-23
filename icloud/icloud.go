// Package icloud contains the SRP primitives that differ between RFC 5054 and
// the Apple iCloud (GSA) implementation.
package icloud

import (
	"crypto"
	"math/big"

	"github.com/bodgit/srp"
	"github.com/bodgit/srp/internal/util"
)

// NewSRP returns a new srp.SRP struct with the iCloud-specific options already
// set.
func NewSRP() (*srp.SRP, error) {
	//nolint:gomnd,wrapcheck
	return srp.NewSRP(
		crypto.SHA256,
		util.Must(srp.GetGroup(2048)),
		srp.X(ComputeX),
		srp.M1(ComputeM1),
	)
}

// ComputeX calculates the SRP x value according to the Apple iCloud
// implementation.
func ComputeX(s *srp.SRP, _ []byte, password, salt []byte) *big.Int {
	return s.HashInt(salt, s.HashBytes([]byte(":"), password))
}

// ComputeM1 calculates the SRP m value according to the Apple iCloud
// implementation.
func ComputeM1(s *srp.SRP, xA, xB *big.Int, xK, identity, salt []byte) []byte {
	// M1 = H(H(N) XOR H(PAD(g)) | H(U) | s | A | B | K)
	xor := make([]byte, s.Hash().New().Size())
	_ = srp.XorBytes(xor, s.HashBytes(s.Group().N.Bytes()), s.HashBytes(util.Pad(s.Group().G, s.Group().Size)))

	return s.HashBytes(xor, s.HashBytes(identity), salt, xA.Bytes(), xB.Bytes(), xK)
}
