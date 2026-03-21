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

// SignDigest signs the given hash digest using the private key.
//
// The algorithm follows GOST R 34.10-2012 (RFC 7091, Section 6.1):
//  1. e = digest mod q; if e == 0, set e = 1
//  2. Generate random k in [1, q-1]
//  3. C = k * P (base point)
//  4. r = C.x mod q; if r == 0, retry with new k
//  5. s = (r*d + k*e) mod q; if s == 0, retry with new k
//  6. Signature = LE(s) || LE(r) (64 bytes)
func (priv *PrivateKey) SignDigest(digest []byte, random io.Reader) ([]byte, error) {
	return priv.signDigestInternal(digest, random, nil)
}

// signDigestInternal is the internal sign implementation that optionally
// accepts a fixed k for KAT testing.
func (priv *PrivateKey) signDigestInternal(digest []byte, random io.Reader, fixedK *big.Int) ([]byte, error) {
	if priv.Curve == nil {
		return nil, errors.New("gost341012: curve is nil")
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		return nil, errors.New("gost341012: invalid private key")
	}

	c := priv.Curve
	q := c.Q
	one := big.NewInt(1)

	// Step 1: e = hash mod q; if e == 0, e = 1.
	e := new(big.Int).SetBytes(digest)
	e.Mod(e, q)
	if e.Sign() == 0 {
		e.Set(one)
	}

	qMinusOne := new(big.Int).Sub(q, one)

	for {
		// Step 2: random k or fixed k for testing.
		var k *big.Int
		if fixedK != nil {
			k = new(big.Int).Set(fixedK)
		} else {
			var err error
			for {
				k, err = randInt(random, qMinusOne)
				if err != nil {
					return nil, err
				}
				if k.Sign() > 0 {
					break
				}
			}
		}

		// Step 3: C = k * P
		cx, _ := c.ScalarBaseMult(k)
		if cx == nil {
			if fixedK != nil {
				return nil, errors.New("gost341012: fixed k produced point at infinity")
			}
			continue
		}

		// Step 4: r = C.x mod q
		r := new(big.Int).Mod(cx, q)
		if r.Sign() == 0 {
			if fixedK != nil {
				return nil, errors.New("gost341012: fixed k produced r == 0")
			}
			continue
		}

		// Step 5: s = (r*d + k*e) mod q
		s := new(big.Int).Mul(r, priv.D)
		s.Mod(s, q)
		ke := new(big.Int).Mul(k, e)
		ke.Mod(ke, q)
		s.Add(s, ke)
		s.Mod(s, q)
		if s.Sign() == 0 {
			if fixedK != nil {
				return nil, errors.New("gost341012: fixed k produced s == 0")
			}
			continue
		}

		// Step 6: signature = LE(s) || LE(r)
		size := c.ByteSize()
		sig := make([]byte, 2*size)
		copy(sig[:size], bigIntToLE(s, size))
		copy(sig[size:], bigIntToLE(r, size))
		return sig, nil
	}
}

// VerifyDigest verifies a signature against the given hash digest.
//
// The algorithm follows GOST R 34.10-2012 (RFC 7091, Section 6.2):
//  1. Parse s and r from signature (LE, 32 bytes each)
//  2. Check 0 < r < q and 0 < s < q
//  3. e = digest mod q; if e == 0, set e = 1
//  4. v = e^(-1) mod q
//  5. z1 = s*v mod q, z2 = -(r*v) mod q
//  6. C = z1*P + z2*Q
//  7. Valid if C.x mod q == r
func (pub *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	if pub.Curve == nil {
		return false, errors.New("gost341012: curve is nil")
	}
	if pub.X == nil || pub.Y == nil {
		return false, errors.New("gost341012: invalid public key")
	}
	c := pub.Curve
	size := c.ByteSize()
	if len(signature) != 2*size {
		return false, errors.New("gost341012: invalid signature size")
	}

	q := c.Q

	// Step 1: extract s and r.
	s := leToBigInt(signature[:size])
	r := leToBigInt(signature[size:])

	// Step 2: range check.
	if s.Sign() <= 0 || s.Cmp(q) >= 0 {
		return false, nil
	}
	if r.Sign() <= 0 || r.Cmp(q) >= 0 {
		return false, nil
	}

	// Step 3: e = hash mod q; if e == 0, e = 1.
	e := new(big.Int).SetBytes(digest)
	e.Mod(e, q)
	if e.Sign() == 0 {
		e.Set(big.NewInt(1))
	}

	// Step 4: v = e^(-1) mod q
	v := new(big.Int).ModInverse(e, q)
	if v == nil {
		return false, errors.New("gost341012: modular inverse failed")
	}

	// Step 5: z1 = s*v mod q, z2 = -(r*v) mod q
	z1 := new(big.Int).Mul(s, v)
	z1.Mod(z1, q)

	z2 := new(big.Int).Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, q)

	// Step 6: C = z1*P + z2*Q
	x1, y1 := c.ScalarBaseMult(z1)
	x2, y2 := c.ScalarMult(pub.X, pub.Y, z2)
	cx, _ := c.pointAdd(x1, y1, x2, y2)

	if cx == nil {
		return false, nil
	}

	// Step 7: check C.x mod q == r
	cx.Mod(cx, q)
	return cx.Cmp(r) == 0, nil
}
