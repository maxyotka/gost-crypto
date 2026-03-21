// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341012 implements the GOST R 34.10-2012 digital signature
// algorithm (RFC 7091, RFC 7836).
//
// Both 256-bit and 512-bit curves are supported. Use CurveParamSetA()
// for the recommended 256-bit curve, or Curve512ParamSetA/B/C() for
// 512-bit curves required by higher security classes (КС2+).
//
// Keys and signatures use little-endian byte order.
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

// ByteSize returns the size of a single coordinate in bytes.
func (c *Curve) ByteSize() int {
	return (c.P.BitLen() + 7) / 8
}

// --- 256-bit curves ---

// CurveParamSetA returns the id-tc26-gost-3410-2012-256-paramSetA curve (RFC 7836).
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

// CurveParamSetB returns the id-tc26-gost-3410-2012-256-paramSetB curve
// (CryptoPro-A, OID 1.2.643.2.2.35.1).
func CurveParamSetB() *Curve {
	return &Curve{
		P: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
		A: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
		B: mustHex("A6"),
		Q: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
		X: mustHex("1"),
		Y: mustHex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
	}
}

// CurveParamSetC returns the id-tc26-gost-3410-2012-256-paramSetC curve
// (CryptoPro-B, OID 1.2.643.2.2.35.2).
func CurveParamSetC() *Curve {
	return &Curve{
		P: mustHex("8000000000000000000000000000000000000000000000000000000000000C99"),
		A: mustHex("8000000000000000000000000000000000000000000000000000000000000C96"),
		B: mustHex("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"),
		Q: mustHex("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
		X: mustHex("1"),
		Y: mustHex("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"),
	}
}

// CurveParamSetD returns the id-tc26-gost-3410-2012-256-paramSetD curve
// (CryptoPro-C, OID 1.2.643.2.2.35.3).
func CurveParamSetD() *Curve {
	return &Curve{
		P: mustHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B"),
		A: mustHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
		B: mustHex("805A"),
		Q: mustHex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"),
		X: mustHex("0"),
		Y: mustHex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"),
	}
}

// --- 512-bit curves ---

// Curve512ParamSetA returns the id-tc26-gost-3410-2012-512-paramSetA curve (RFC 7836).
func Curve512ParamSetA() *Curve {
	return &Curve{
		P: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
		A: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
		B: mustHex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
		Q: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
		X: mustHex("3"),
		Y: mustHex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
	}
}

// Curve512ParamSetB returns the id-tc26-gost-3410-2012-512-paramSetB curve (RFC 7836).
func Curve512ParamSetB() *Curve {
	return &Curve{
		P: mustHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"),
		A: mustHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"),
		B: mustHex("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"),
		Q: mustHex("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"),
		X: mustHex("2"),
		Y: mustHex("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"),
	}
}

// Curve512ParamSetC returns the id-tc26-gost-3410-2012-512-paramSetC curve (RFC 7836).
func Curve512ParamSetC() *Curve {
	return &Curve{
		P: mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
		A: mustHex("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"),
		B: mustHex("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"),
		Q: mustHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED"),
		X: mustHex("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"),
		Y: mustHex("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"),
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
