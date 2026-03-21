// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341012 implements the GOST R 34.10-2012 digital signature
// algorithm (RFC 7091, RFC 7836).
//
// The default curve is id-tc26-gost-3410-2012-256-paramSetA.
// Keys and signatures use little-endian byte order for compatibility
// with gogost and existing deployments.
package gost341012

import "math/big"

// Curve holds the parameters of an elliptic curve y^2 = x^3 + a*x + b (mod p)
// together with a base point (X, Y) of order Q.
type Curve struct {
	P *big.Int // field prime
	A *big.Int // curve coefficient a
	B *big.Int // curve coefficient b
	Q *big.Int // base point order
	X *big.Int // base point x
	Y *big.Int // base point y
}

// CurveParamSetA returns the id-tc26-gost-3410-2012-256-paramSetA curve.
func CurveParamSetA() *Curve {
	return &Curve{
		P: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
		A: mustHex("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
		B: mustHex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
		Q: mustHex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
		X: mustHex("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
		Y: mustHex("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
	}
}

// mustHex parses a hexadecimal string into *big.Int, panicking on failure.
func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("gost341012: bad hex constant: " + s)
	}
	return v
}

// pointAdd computes (x3, y3) = (x1, y1) + (x2, y2) on curve c
// using affine coordinates.
// The point at infinity is represented as (nil, nil).
func (c *Curve) pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// Handle identity element (point at infinity).
	if x1 == nil || y1 == nil {
		return x2, y2
	}
	if x2 == nil || y2 == nil {
		return x1, y1
	}

	p := c.P

	// Check if points are the same — use doubling.
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return c.pointDouble(x1, y1)
	}

	// Check if points are inverses of each other: x1 == x2, y1 == -y2.
	if x1.Cmp(x2) == 0 {
		return nil, nil
	}

	// lambda = (y2 - y1) / (x2 - x1) mod p
	dy := new(big.Int).Sub(y2, y1)
	dy.Mod(dy, p)
	dx := new(big.Int).Sub(x2, x1)
	dx.Mod(dx, p)
	dxInv := new(big.Int).ModInverse(dx, p)
	lambda := new(big.Int).Mul(dy, dxInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// pointDouble computes (x3, y3) = 2 * (x1, y1) on curve c.
func (c *Curve) pointDouble(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if x1 == nil || y1 == nil {
		return nil, nil
	}

	p := c.P

	// If y1 == 0, the result is point at infinity.
	if y1.Sign() == 0 {
		return nil, nil
	}

	// lambda = (3 * x1^2 + a) / (2 * y1) mod p
	num := new(big.Int).Mul(x1, x1)
	num.Mod(num, p)
	num.Mul(num, big.NewInt(3))
	num.Add(num, c.A)
	num.Mod(num, p)

	den := new(big.Int).Mul(big.NewInt(2), y1)
	den.Mod(den, p)
	denInv := new(big.Int).ModInverse(den, p)

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - 2*x1 mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x1)
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// ScalarMult computes (rx, ry) = k * (x, y) using the Montgomery ladder.
//
// The Montgomery ladder performs the same number of point additions and
// doublings regardless of the scalar bits, providing resistance to
// simple power analysis (SPA) attacks.
//
// Note: math/big arithmetic is inherently variable-time. For stronger
// timing guarantees, a constant-time field implementation is required.
func (c *Curve) ScalarMult(x, y *big.Int, k *big.Int) (*big.Int, *big.Int) {
	var r0x, r0y *big.Int                                     // point at infinity
	r1x, r1y := new(big.Int).Set(x), new(big.Int).Set(y)

	for i := k.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			r1x, r1y = c.pointAdd(r0x, r0y, r1x, r1y)
			r0x, r0y = c.pointDouble(r0x, r0y)
		} else {
			r0x, r0y = c.pointAdd(r0x, r0y, r1x, r1y)
			r1x, r1y = c.pointDouble(r1x, r1y)
		}
	}
	return r0x, r0y
}

// ScalarBaseMult computes k * G where G is the base point.
func (c *Curve) ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return c.ScalarMult(c.X, c.Y, k)
}

// IsOnCurve reports whether the point (x, y) lies on the curve.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	// y^2 mod p
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, c.P)

	// x^3 + a*x + b mod p
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, c.P)
	rhs.Mul(rhs, x)
	rhs.Mod(rhs, c.P)
	ax := new(big.Int).Mul(c.A, x)
	ax.Mod(ax, c.P)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, c.B)
	rhs.Mod(rhs, c.P)

	return lhs.Cmp(rhs) == 0
}
