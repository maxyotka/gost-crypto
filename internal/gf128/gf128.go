// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gf128 implements multiplication in GF(2^128) with the GOST R 34.13-2015
// polynomial for use in MGM (Multilinear Galois Mode) with Kuznyechik (128-bit block).
//
// The irreducible polynomial is: x^128 + x^7 + x^2 + x + 1.
// Elements are stored as 16-byte big-endian arrays where the LSB of byte[15]
// corresponds to x^0 (the identity coefficient) and the MSB of byte[0]
// corresponds to x^127.
package gf128

// polynomial is the low 8 bits of the GOST reduction polynomial
// x^128 + x^7 + x^2 + x + 1  =>  0x87  (bits 7,2,1,0 set = 0b10000111).
const polynomial = 0x87

// Mul performs constant-time multiplication of x and y in GF(2^128) using the
// GOST polynomial. The implementation uses a double-and-add approach operating
// on two uint64 limbs; it never indexes into tables based on secret data.
func Mul(x, y *[16]byte) [16]byte {
	// Load x into two 64-bit limbs (big-endian).
	xHi := beUint64(x[0:8])
	xLo := beUint64(x[8:16])

	// Load y into two 64-bit limbs (big-endian).
	yHi := beUint64(y[0:8])
	yLo := beUint64(y[8:16])

	// Accumulator z = 0.
	var zHi, zLo uint64

	// Iterate over every bit of y from LSB to MSB (bit 0 = x^0 = identity).
	for i := 0; i < 128; i++ {
		// If the current LSB of y is set, XOR x into z.
		mask := ctMask(yLo & 1)
		zHi ^= xHi & mask
		zLo ^= xLo & mask

		// Shift y right by 1 (advance to next bit).
		yLo = (yLo >> 1) | (yHi << 63)
		yHi >>= 1

		// Shift x left by 1 (multiply by alpha in GF(2^128)).
		// If the high bit was set, reduce by XORing the polynomial.
		carry := ctMask(xHi >> 63)
		xHi = (xHi << 1) | (xLo >> 63)
		xLo <<= 1
		xLo ^= uint64(polynomial) & carry
	}

	// Store result in big-endian.
	var result [16]byte
	bePutUint64(result[0:8], zHi)
	bePutUint64(result[8:16], zLo)
	return result
}

// ctMask returns 0xFFFFFFFFFFFFFFFF if b is 1, or 0 if b is 0.
// Used for constant-time conditional selection.
func ctMask(b uint64) uint64 {
	return uint64(-int64(b & 1))
}

// beUint64 reads a big-endian uint64.
func beUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// bePutUint64 writes a big-endian uint64.
func bePutUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}
