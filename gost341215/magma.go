// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	// MagmaBlockSize is the Magma block size in bytes (64 bits).
	MagmaBlockSize = 8
	// MagmaKeySize is the Magma key size in bytes (256 bits).
	MagmaKeySize = 32
	magmaRounds  = 32
)

// magmaKeyOrder defines the subkey index for each of the 32 rounds.
// Rounds 1-24 use keys 0..7 cyclically; rounds 25-32 use keys 7..0.
var magmaKeyOrder = [magmaRounds]int{
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
}

type magma struct {
	subkeys [8]uint32
}

// NewMagma creates a new Magma cipher.Block from a 32-byte key.
func NewMagma(key []byte) (cipher.Block, error) {
	if len(key) != MagmaKeySize {
		return nil, errors.New("gost341215: invalid key size (must be 32 bytes)")
	}
	m := new(magma)
	// Split the 256-bit key into 8 32-bit subkeys (big-endian per RFC 8891).
	// K_1 = key[0:4], K_2 = key[4:8], ..., K_8 = key[28:32].
	for i := 0; i < 8; i++ {
		m.subkeys[i] = binary.BigEndian.Uint32(key[i*4 : i*4+4])
	}
	return m, nil
}

func (m *magma) BlockSize() int { return MagmaBlockSize }

func (m *magma) Encrypt(dst, src []byte) {
	if len(src) < MagmaBlockSize {
		panic("gost341215: input not full block")
	}
	if len(dst) < MagmaBlockSize {
		panic("gost341215: output not full block")
	}

	// Read the two 32-bit halves (big-endian per RFC 8891).
	// (a_1, a_0) where a_1 = src[0:4], a_0 = src[4:8].
	a1 := binary.BigEndian.Uint32(src[0:4])
	a0 := binary.BigEndian.Uint32(src[4:8])

	// Rounds 1..31: G[K_i](a_1, a_0) = (a_0, g[K_i](a_0) XOR a_1).
	for i := 0; i < magmaRounds-1; i++ {
		a1, a0 = a0, magmaG(a0+m.subkeys[magmaKeyOrder[i]])^a1
	}
	// Round 32 (G*): no swap.
	// G*[K_32](a_1, a_0) = (g[K_32](a_0) XOR a_1, a_0).
	a1 = magmaG(a0+m.subkeys[magmaKeyOrder[magmaRounds-1]]) ^ a1

	binary.BigEndian.PutUint32(dst[0:4], a1)
	binary.BigEndian.PutUint32(dst[4:8], a0)
}

func (m *magma) Decrypt(dst, src []byte) {
	if len(src) < MagmaBlockSize {
		panic("gost341215: input not full block")
	}
	if len(dst) < MagmaBlockSize {
		panic("gost341215: output not full block")
	}

	// Read the two 32-bit halves (big-endian).
	// After encryption: ciphertext = (a_1, a_0).
	a1 := binary.BigEndian.Uint32(src[0:4])
	a0 := binary.BigEndian.Uint32(src[4:8])

	// Decryption: apply rounds in reverse order.
	// First undo the G* (no swap) from the last encryption round.
	a1 = magmaG(a0+m.subkeys[magmaKeyOrder[magmaRounds-1]]) ^ a1

	// Then undo rounds 31..1 in reverse.
	for i := magmaRounds - 2; i >= 0; i-- {
		a1, a0 = magmaG(a1+m.subkeys[magmaKeyOrder[i]])^a0, a1
	}

	binary.BigEndian.PutUint32(dst[0:4], a1)
	binary.BigEndian.PutUint32(dst[4:8], a0)
}

// magmaG applies the Magma substitution and circular left shift by 11 bits.
// g[k](a) = t(a [+] k) <<<_11
// Here val = a + k (mod 2^32) has already been computed by the caller.
func magmaG(val uint32) uint32 {
	// Apply 8 S-boxes (4 bits each) using precomputed pair tables.
	var result uint32
	result |= magmaK87[0][byte(val)]
	result |= magmaK87[1][byte(val>>8)] << 8
	result |= magmaK87[2][byte(val>>16)] << 16
	result |= magmaK87[3][byte(val>>24)] << 24
	// Circular left shift by 11.
	return (result << 11) | (result >> 21)
}
