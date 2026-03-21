// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341012

import (
	"errors"
	"io"
	"math/big"
)

const (
	// PrivateKeySize is the size of a raw private key in bytes.
	PrivateKeySize = 32
	// PublicKeySize is the size of a raw public key in bytes: LE(X) || LE(Y).
	PublicKeySize = 64
	// SignatureSize is the size of a signature in bytes: LE(s) || LE(r).
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

// Raw returns the private key as a 32-byte little-endian slice.
func (priv *PrivateKey) Raw() []byte {
	return bigIntToLE(priv.D, PrivateKeySize)
}

// Raw returns the public key as 64 bytes: LE(X) || LE(Y).
func (pub *PublicKey) Raw() []byte {
	out := make([]byte, PublicKeySize)
	copy(out[:PrivateKeySize], bigIntToLE(pub.X, PrivateKeySize))
	copy(out[PrivateKeySize:], bigIntToLE(pub.Y, PrivateKeySize))
	return out
}

// NewPrivateKey creates a PrivateKey from a 32-byte little-endian raw key.
func NewPrivateKey(curve *Curve, raw []byte) (*PrivateKey, error) {
	if len(raw) != PrivateKeySize {
		return nil, errors.New("gost341012: invalid private key size")
	}
	if curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	d := leToBigInt(raw)
	if d.Sign() <= 0 || d.Cmp(curve.Q) >= 0 {
		return nil, errors.New("gost341012: private key out of range")
	}
	return &PrivateKey{Curve: curve, D: d}, nil
}

// NewPublicKey creates a PublicKey from a 64-byte raw key: LE(X) || LE(Y).
func NewPublicKey(curve *Curve, raw []byte) (*PublicKey, error) {
	if len(raw) != PublicKeySize {
		return nil, errors.New("gost341012: invalid public key size")
	}
	if curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	x := leToBigInt(raw[:PrivateKeySize])
	y := leToBigInt(raw[PrivateKeySize:])
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
