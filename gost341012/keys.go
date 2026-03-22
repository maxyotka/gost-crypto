// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341012

import (
	"crypto"
	"errors"
	"io"
	"math/big"
)

// Ensure PrivateKey implements crypto.Signer.
var _ crypto.Signer = (*PrivateKey)(nil)

const (
	// PrivateKeySize is the size of a 256-bit private key in bytes.
	// For curve-independent code, use Curve.ByteSize().
	PrivateKeySize = 32
	// PublicKeySize is the size of a 256-bit public key in bytes: LE(X) || LE(Y).
	// For curve-independent code, use 2 * Curve.ByteSize().
	PublicKeySize = 64
	// SignatureSize is the size of a 256-bit signature in bytes: LE(s) || LE(r).
	// For curve-independent code, use 2 * Curve.ByteSize().
	SignatureSize = 64
)

// PrivateKey represents a GOST R 34.10-2012 private key.
type PrivateKey struct {
	Curve *Curve
	D     *big.Int
}

// PublicKey represents a GOST R 34.10-2012 public key.
type PublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

// GenerateKey generates a new private/public key pair for the given curve
// using the provided random source.
func GenerateKey(curve *Curve, random io.Reader) (*PrivateKey, *PublicKey, error) {
	if curve == nil {
		return nil, nil, errors.New("gost341012: curve is nil")
	}
	if random == nil {
		return nil, nil, errors.New("gost341012: random source is nil")
	}

	one := big.NewInt(1)
	qMinusOne := new(big.Int).Sub(curve.Q, one)

	// Generate d in [1, q-1].
	for {
		d, err := randInt(random, qMinusOne)
		if err != nil {
			return nil, nil, err
		}
		// d must be >= 1
		if d.Sign() == 0 {
			continue
		}

		priv := &PrivateKey{Curve: curve, D: d}
		pub, err := priv.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	}
}

// PublicKey computes the public key Q = d * G.
func (priv *PrivateKey) PublicKey() (*PublicKey, error) {
	if priv.Curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		return nil, errors.New("gost341012: invalid private key")
	}
	x, y := priv.Curve.ScalarBaseMult(priv.D)
	if x == nil || y == nil {
		return nil, errors.New("gost341012: scalar multiplication resulted in point at infinity")
	}
	return &PublicKey{Curve: priv.Curve, X: x, Y: y}, nil
}

// Public returns the public key corresponding to this private key.
// Implements crypto.Signer.
func (priv *PrivateKey) Public() crypto.PublicKey {
	pub, err := priv.PublicKey()
	if err != nil {
		return nil
	}
	return pub
}

// Sign signs digest with the private key using GOST R 34.10-2012.
// The opts argument is ignored — the digest is used directly.
// Implements crypto.Signer.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignDigest(digest, rand)
}

// Raw returns the private key as a little-endian byte slice.
func (priv *PrivateKey) Raw() []byte {
	size := priv.Curve.ByteSize()
	return bigIntToLE(priv.D, size)
}

// Raw returns the public key as LE(X) || LE(Y).
func (pub *PublicKey) Raw() []byte {
	size := pub.Curve.ByteSize()
	out := make([]byte, 2*size)
	copy(out[:size], bigIntToLE(pub.X, size))
	copy(out[size:], bigIntToLE(pub.Y, size))
	return out
}

// NewPrivateKey creates a PrivateKey from a little-endian raw key.
// The raw key length must match the curve's byte size.
func NewPrivateKey(curve *Curve, raw []byte) (*PrivateKey, error) {
	if curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	if len(raw) != curve.ByteSize() {
		return nil, errors.New("gost341012: invalid private key size")
	}
	d := leToBigInt(raw)
	if d.Sign() <= 0 || d.Cmp(curve.Q) >= 0 {
		return nil, errors.New("gost341012: private key out of range")
	}
	return &PrivateKey{Curve: curve, D: d}, nil
}

// NewPublicKey creates a PublicKey from a raw key: LE(X) || LE(Y).
// The raw key length must be 2 * curve.ByteSize().
func NewPublicKey(curve *Curve, raw []byte) (*PublicKey, error) {
	if curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	size := curve.ByteSize()
	if len(raw) != 2*size {
		return nil, errors.New("gost341012: invalid public key size")
	}
	x := leToBigInt(raw[:size])
	y := leToBigInt(raw[size:])
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("gost341012: public key point is not on the curve")
	}
	return &PublicKey{Curve: curve, X: x, Y: y}, nil
}

// bigIntToLE encodes v as a little-endian byte slice of length size.
func bigIntToLE(v *big.Int, size int) []byte {
	b := v.Bytes() // big-endian
	out := make([]byte, size)
	// Reverse into out (little-endian), truncating or zero-padding as needed.
	for i, j := 0, len(b)-1; j >= 0 && i < size; i, j = i+1, j-1 {
		out[i] = b[j]
	}
	return out
}

// leToBigInt decodes a little-endian byte slice into *big.Int.
func leToBigInt(le []byte) *big.Int {
	// Reverse to big-endian.
	be := make([]byte, len(le))
	for i, j := 0, len(le)-1; j >= 0; i, j = i+1, j-1 {
		be[i] = le[j]
	}
	return new(big.Int).SetBytes(be)
}

// randInt returns a uniform random value in [0, max).
func randInt(random io.Reader, max *big.Int) (*big.Int, error) {
	// Number of bytes needed.
	byteLen := (max.BitLen() + 7) / 8
	buf := make([]byte, byteLen)

	for {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nil, err
		}
		// Mask extra bits in the top byte to avoid bias.
		extraBits := uint(byteLen*8 - max.BitLen())
		if extraBits > 0 {
			buf[0] &= byte((1 << (8 - extraBits)) - 1)
		}
		v := new(big.Int).SetBytes(buf)
		if v.Cmp(max) < 0 {
			return v, nil
		}
	}
}
