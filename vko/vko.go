// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package vko implements the VKO GOST R 34.10-2012 key agreement
// algorithm (RFC 7836, Section 4.3).
//
// The functions KEK256 and KEK512 compute 256-bit and 512-bit key
// encryption keys respectively by performing an elliptic-curve
// Diffie-Hellman exchange and hashing the resulting shared point
// with Stribog.
package vko

import (
	"errors"
	"math/big"

	"github.com/maxyotka/gost-crypto/gost341012"
	"github.com/maxyotka/gost-crypto/gost341112"
)

// KEK256 computes a 256-bit key encryption key using VKO GOST R 34.10-2012.
// ukm is the User Keying Material (must not be zero).
// Returns 32 bytes: Stribog-256(LE(x) || LE(y)) where (x,y) = (ukm * d) * Q_peer.
func KEK256(priv *gost341012.PrivateKey, pub *gost341012.PublicKey, ukm *big.Int) ([]byte, error) {
	point, err := sharedPoint(priv, pub, ukm)
	if err != nil {
		return nil, err
	}

	h := gost341112.New256()
	h.Write(point)
	return h.Sum(nil), nil
}

// KEK512 computes a 512-bit key encryption key using VKO GOST R 34.10-2012.
// ukm is the User Keying Material (must not be zero).
// Returns 64 bytes: Stribog-512(LE(x) || LE(y)) where (x,y) = (ukm * d) * Q_peer.
func KEK512(priv *gost341012.PrivateKey, pub *gost341012.PublicKey, ukm *big.Int) ([]byte, error) {
	point, err := sharedPoint(priv, pub, ukm)
	if err != nil {
		return nil, err
	}

	h := gost341112.New512()
	h.Write(point)
	return h.Sum(nil), nil
}

// coordSize is the size of a single coordinate in bytes (256-bit curve).
const coordSize = 32

// sharedPoint computes the VKO shared point and returns LE(x) || LE(y).
//
// Algorithm (RFC 7836, Section 4.3):
//  1. scalar = ukm * d (mod q)
//  2. P = scalar * Q_peer
//  3. If P is the point at infinity, return error
//  4. Return LE(x) || LE(y), 32 bytes each
func sharedPoint(priv *gost341012.PrivateKey, pub *gost341012.PublicKey, ukm *big.Int) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.D == nil {
		return nil, errors.New("vko: invalid private key")
	}
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, errors.New("vko: invalid public key")
	}
	if ukm == nil || ukm.Sign() == 0 {
		return nil, errors.New("vko: ukm must not be zero")
	}

	curve := priv.Curve

	// scalar = ukm * d (mod q)
	scalar := new(big.Int).Mul(ukm, priv.D)
	scalar.Mod(scalar, curve.Q)

	// P = scalar * Q_peer
	px, py := curve.ScalarMult(pub.X, pub.Y, scalar)

	// Check for point at infinity.
	if px == nil || py == nil {
		return nil, errors.New("vko: result is point at infinity")
	}

	// Encode as LE(x) || LE(y), matching GOST byte-order convention.
	out := make([]byte, 2*coordSize)
	copy(out[:coordSize], bigIntToLE(px, coordSize))
	copy(out[coordSize:], bigIntToLE(py, coordSize))

	// Best-effort zeroization of sensitive intermediates.
	scalar.SetInt64(0)
	px.SetInt64(0)
	py.SetInt64(0)

	return out, nil
}

// bigIntToLE encodes v as a little-endian byte slice of the given size.
func bigIntToLE(v *big.Int, size int) []byte {
	b := v.Bytes() // big-endian
	out := make([]byte, size)
	for i, j := 0, len(b)-1; j >= 0 && i < size; i, j = i+1, j-1 {
		out[i] = b[j]
	}
	return out
}
