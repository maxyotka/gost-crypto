// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gf64 implements multiplication in GF(2^64) with the GOST R 34.13-2015
// polynomial for use in MGM (Multilinear Galois Mode) with Magma (64-bit block).
//
// The irreducible polynomial is: x^64 + x^4 + x^3 + x + 1.
// Elements are stored as 8-byte big-endian arrays where the LSB of byte[7]
// corresponds to x^0 (the identity coefficient) and the MSB of byte[0]
// corresponds to x^63.
package gf64

// polynomial is the low 8 bits of the GOST reduction polynomial
// x^64 + x^4 + x^3 + x + 1  =>  0x1B  (bits 4,3,1,0 set = 0b00011011).
const polynomial = 0x1B

// Mul performs constant-time multiplication of x and y in GF(2^64) using the
// GOST polynomial. The implementation uses a double-and-add approach operating
// on a single uint64 limb; it never indexes into tables based on secret data.
func Mul(x, y *[8]byte) [8]byte {
	// Load x and y as big-endian uint64 values.
	xv := beUint64(x[:])
	yv := beUint64(y[:])

	// Accumulator z = 0.
	var z uint64

	// Iterate over every bit of y from LSB to MSB (bit 0 = x^0 = identity).
	for i := 0; i < 64; i++ {
		// If the current LSB of y is set, XOR x into z.
		mask := ctMask(yv & 1)
		z ^= xv & mask

		// Shift y right by 1 (advance to next bit).
		yv >>= 1

		// Shift x left by 1 (multiply by alpha in GF(2^64)).
		// If the high bit was set before shift, reduce by XORing the polynomial.
		carry := ctMask(xv >> 63)
		xv <<= 1
		xv ^= uint64(polynomial) & carry
	}

	// Store result in big-endian.
	var result [8]byte
	bePutUint64(result[:], z)
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
