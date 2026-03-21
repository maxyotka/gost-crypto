// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341215 implements the Kuznechik (Кузнечик) and Magma block ciphers
// defined in ГОСТ Р 34.12-2015 (GOST R 34.12-2015, RFC 7801).
package gost341215

import (
	"crypto/cipher"
	"errors"

	"github.com/maxyotka/gost-crypto/internal/subtle"
)

const (
	// KuznechikBlockSize is the Kuznechik block size in bytes (128 bits).
	KuznechikBlockSize = 16
	// KuznechikKeySize is the Kuznechik key size in bytes (256 bits).
	KuznechikKeySize = 32
	kuznechikRounds  = 10
)

type kuznechik struct {
	enc [kuznechikRounds][KuznechikBlockSize]byte
	dec [kuznechikRounds][KuznechikBlockSize]byte
}

// NewKuznechik creates a new Kuznechik cipher.Block from a 32-byte key.
func NewKuznechik(key []byte) (cipher.Block, error) {
	if len(key) != KuznechikKeySize {
		return nil, errors.New("gost341215: invalid key size (must be 32 bytes)")
	}
	c := new(kuznechik)
	c.expandKey(key)
	return c, nil
}

func (c *kuznechik) BlockSize() int { return KuznechikBlockSize }

func (c *kuznechik) Encrypt(dst, src []byte) {
	if len(src) < KuznechikBlockSize {
		panic("gost341215: input not full block")
	}
	if len(dst) < KuznechikBlockSize {
		panic("gost341215: output not full block")
	}

	var block [KuznechikBlockSize]byte
	copy(block[:], src[:KuznechikBlockSize])

	// Rounds 1..9: XOR with round key, then combined S+L via precomputed table.
	for i := 0; i < kuznechikRounds-1; i++ {
		xorBlocks(&block, &c.enc[i])
		var result [KuznechikBlockSize]byte
		for p := 0; p < KuznechikBlockSize; p++ {
			t := &slTable[p][block[p]]
			result[0] ^= t[0]
			result[1] ^= t[1]
			result[2] ^= t[2]
			result[3] ^= t[3]
			result[4] ^= t[4]
			result[5] ^= t[5]
			result[6] ^= t[6]
			result[7] ^= t[7]
			result[8] ^= t[8]
			result[9] ^= t[9]
			result[10] ^= t[10]
			result[11] ^= t[11]
			result[12] ^= t[12]
			result[13] ^= t[13]
			result[14] ^= t[14]
			result[15] ^= t[15]
		}
		block = result
	}
	// Round 10: XOR with last round key only.
	xorBlocks(&block, &c.enc[kuznechikRounds-1])

	copy(dst[:KuznechikBlockSize], block[:])
}

func (c *kuznechik) Decrypt(dst, src []byte) {
	if len(src) < KuznechikBlockSize {
		panic("gost341215: input not full block")
	}
	if len(dst) < KuznechikBlockSize {
		panic("gost341215: output not full block")
	}

	var block [KuznechikBlockSize]byte
	copy(block[:], src[:KuznechikBlockSize])

	// Inverse rounds: 10, 9, ..., 1.
	xorBlocks(&block, &c.dec[0])
	for i := 1; i < kuznechikRounds; i++ {
		// Inverse L-transform via precomputed table.
		var result [KuznechikBlockSize]byte
		for p := 0; p < KuznechikBlockSize; p++ {
			t := &lInvTable[p][block[p]]
			result[0] ^= t[0]
			result[1] ^= t[1]
			result[2] ^= t[2]
			result[3] ^= t[3]
			result[4] ^= t[4]
			result[5] ^= t[5]
			result[6] ^= t[6]
			result[7] ^= t[7]
			result[8] ^= t[8]
			result[9] ^= t[9]
			result[10] ^= t[10]
			result[11] ^= t[11]
			result[12] ^= t[12]
			result[13] ^= t[13]
			result[14] ^= t[14]
			result[15] ^= t[15]
		}
		block = result
		sInvTransform(&block)
		xorBlocks(&block, &c.dec[i])
	}

	copy(dst[:KuznechikBlockSize], block[:])
}

// expandKey derives 10 round keys from the 256-bit master key using
// the Feistel network described in RFC 7801 Section 4.3.
func (c *kuznechik) expandKey(key []byte) {
	var k1, k2 [KuznechikBlockSize]byte
	copy(k1[:], key[:KuznechikBlockSize])
	copy(k2[:], key[KuznechikBlockSize:])

	c.enc[0] = k1
	c.enc[1] = k2

	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			// Compute iteration constant C[8*i+j+1] = L(8*i+j+1).
			cval := iterConst(8*i + j + 1)

			var tmp [KuznechikBlockSize]byte
			copy(tmp[:], k1[:])
			xorBlocks(&tmp, &cval)
			sTransform(&tmp)
			lTransform(&tmp)
			xorBlocks(&tmp, &k2)

			k2 = k1
			k1 = tmp
		}
		c.enc[2*i+2] = k1
		c.enc[2*i+3] = k2
	}

	// Precompute decryption keys (reverse order).
	for i := 0; i < kuznechikRounds; i++ {
		c.dec[i] = c.enc[kuznechikRounds-1-i]
	}

	// Zeroize temporary key material.
	subtle.Zeroize(k1[:])
	subtle.Zeroize(k2[:])
}

// iterConst computes the iteration constant C[num] = L(num),
// where num is placed into the 16th byte of a zero block and L is applied.
func iterConst(num int) [KuznechikBlockSize]byte {
	var val [KuznechikBlockSize]byte
	val[KuznechikBlockSize-1] = byte(num)
	lTransform(&val)
	return val
}

// gfMul multiplies two elements in GF(2^8) with the reducing polynomial
// x^8 + x^7 + x^6 + x + 1 (0x1C3).
func gfMul(a, b byte) byte {
	var result byte
	aa := a
	bb := b
	for bb != 0 {
		if bb&1 != 0 {
			result ^= aa
		}
		hi := aa & 0x80
		aa <<= 1
		if hi != 0 {
			aa ^= 0xC3 // x^8 mod (x^8+x^7+x^6+x+1) = x^7+x^6+x+1 = 0xC3
		}
		bb >>= 1
	}
	return result
}

// rTransform is the R-transformation: one step of the shift register
// using GF(2^8) multiplication with the L coefficients.
func rTransform(block *[KuznechikBlockSize]byte) {
	var feedback byte
	for i := 0; i < KuznechikBlockSize; i++ {
		feedback ^= gfMul(block[i], lCoeffs[i])
	}
	// Shift right by 1 byte and prepend feedback.
	copy(block[1:], block[:KuznechikBlockSize-1])
	block[0] = feedback
}

// rInvTransform is the inverse R-transformation.
func rInvTransform(block *[KuznechikBlockSize]byte) {
	first := block[0]
	copy(block[:], block[1:])
	block[KuznechikBlockSize-1] = first

	var feedback byte
	for i := 0; i < KuznechikBlockSize; i++ {
		feedback ^= gfMul(block[i], lCoeffs[i])
	}
	block[KuznechikBlockSize-1] = feedback
}

// lTransform applies 16 iterations of the R-transformation (the L-transformation).
func lTransform(block *[KuznechikBlockSize]byte) {
	for i := 0; i < KuznechikBlockSize; i++ {
		rTransform(block)
	}
}

// lInvTransform applies 16 iterations of the inverse R-transformation.
func lInvTransform(block *[KuznechikBlockSize]byte) {
	for i := 0; i < KuznechikBlockSize; i++ {
		rInvTransform(block)
	}
}

// sTransform applies the S-box substitution (pi) to each byte.
func sTransform(block *[KuznechikBlockSize]byte) {
	for i := 0; i < KuznechikBlockSize; i++ {
		block[i] = pi[block[i]]
	}
}

// sInvTransform applies the inverse S-box substitution (piInv) to each byte.
func sInvTransform(block *[KuznechikBlockSize]byte) {
	for i := 0; i < KuznechikBlockSize; i++ {
		block[i] = piInv[block[i]]
	}
}

// xorBlocks XORs block a with block b, storing result in a.
func xorBlocks(a, b *[KuznechikBlockSize]byte) {
	for i := 0; i < KuznechikBlockSize; i++ {
		a[i] ^= b[i]
	}
}
