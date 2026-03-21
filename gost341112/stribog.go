// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341112 implements the Stribog hash function defined in
// ГОСТ Р 34.11-2012 (GOST R 34.11-2012, RFC 6986).
//
// Two hash sizes are supported: 256-bit and 512-bit.
//
//	h256 := gost341112.New256()
//	h512 := gost341112.New512()
package gost341112

import (
	"encoding/binary"
	"hash"

	"github.com/maxyotka/gost-crypto/internal/subtle"
)

const (
	// Size256 is the size of Stribog-256 checksum in bytes.
	Size256 = 32
	// Size512 is the size of Stribog-512 checksum in bytes.
	Size512 = 64
	// BlockSize is the block size of Stribog in bytes.
	BlockSize = 64
)

type digest struct {
	size   int
	n      uint64
	hsh    [BlockSize]byte
	chk    [BlockSize]byte
	buf    [BlockSize]byte
	bufLen int
}

// New512 returns a new hash.Hash computing the Stribog-512 checksum.
func New512() hash.Hash {
	d := &digest{size: Size512}
	d.Reset()
	return d
}

// New256 returns a new hash.Hash computing the Stribog-256 checksum.
func New256() hash.Hash {
	d := &digest{size: Size256}
	d.Reset()
	return d
}

// Sum256 returns the Stribog-256 checksum of data.
func Sum256(data []byte) [Size256]byte {
	h := New256()
	h.Write(data)
	var out [Size256]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Sum512 returns the Stribog-512 checksum of data.
func Sum512(data []byte) [Size512]byte {
	h := New512()
	h.Write(data)
	var out [Size512]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (d *digest) Reset() {
	d.n = 0
	d.bufLen = 0
	subtle.Zeroize(d.buf[:])
	subtle.Zeroize(d.chk[:])
	if d.size == Size256 {
		for i := range d.hsh {
			d.hsh[i] = 1
		}
	} else {
		subtle.Zeroize(d.hsh[:])
	}
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(data []byte) (int, error) {
	nn := len(data)
	// Fill the buffer first.
	if d.bufLen > 0 {
		n := copy(d.buf[d.bufLen:], data)
		d.bufLen += n
		data = data[n:]
		if d.bufLen == BlockSize {
			d.hsh = g(d.n, d.hsh, d.buf)
			d.chk = add512(d.chk, d.buf)
			d.n += BlockSize * 8
			d.bufLen = 0
		}
	}
	// Process full blocks directly.
	for len(data) >= BlockSize {
		var block [BlockSize]byte
		copy(block[:], data[:BlockSize])
		d.hsh = g(d.n, d.hsh, block)
		d.chk = add512(d.chk, block)
		d.n += BlockSize * 8
		data = data[BlockSize:]
	}
	// Buffer remaining bytes.
	if len(data) > 0 {
		copy(d.buf[:], data)
		d.bufLen = len(data)
	}
	return nn, nil
}

func (d *digest) Sum(in []byte) []byte {
	var buf [BlockSize]byte
	copy(buf[:], d.buf[:d.bufLen])
	buf[d.bufLen] = 1

	hsh := g(d.n, d.hsh, buf)

	var nBuf [BlockSize]byte
	binary.LittleEndian.PutUint64(nBuf[:8], d.n+uint64(d.bufLen)*8)

	hsh = g(0, hsh, nBuf)
	hsh = g(0, hsh, add512(d.chk, buf))

	if d.size == Size256 {
		return append(in, hsh[BlockSize/2:]...)
	}
	return append(in, hsh[:]...)
}

// g is the compression function (pure, no side effects).
// Returns E(LPS(hsh XOR N), data) XOR hsh XOR data.
func g(n uint64, hsh, data [BlockSize]byte) [BlockSize]byte {
	var k [BlockSize]byte
	copy(k[:], hsh[:])
	k[0] ^= byte(n)
	k[1] ^= byte(n >> 8)
	k[2] ^= byte(n >> 16)
	k[3] ^= byte(n >> 24)
	k[4] ^= byte(n >> 32)
	k[5] ^= byte(n >> 40)
	k[6] ^= byte(n >> 48)
	k[7] ^= byte(n >> 56)

	k = lps(k)
	enc := e(k, data)

	var result [BlockSize]byte
	for i := 0; i < BlockSize; i++ {
		result[i] = enc[i] ^ hsh[i] ^ data[i]
	}
	return result
}

// e is the block cipher E(k, msg).
func e(k, msg [BlockSize]byte) [BlockSize]byte {
	for i := 0; i < 12; i++ {
		var xb [BlockSize]byte
		for j := 0; j < BlockSize; j++ {
			xb[j] = k[j] ^ msg[j]
		}
		msg = lps(xb)

		for j := 0; j < BlockSize; j++ {
			xb[j] = k[j] ^ c[i][j]
		}
		k = lps(xb)
	}

	var out [BlockSize]byte
	for j := 0; j < BlockSize; j++ {
		out[j] = k[j] ^ msg[j]
	}
	return out
}

// add512 adds two 512-bit values as little-endian integers.
func add512(a, b [BlockSize]byte) [BlockSize]byte {
	var result [BlockSize]byte
	var carry uint16
	for i := 0; i < BlockSize; i++ {
		carry += uint16(a[i]) + uint16(b[i])
		result[i] = byte(carry)
		carry >>= 8
	}
	return result
}

// lps performs S (substitution), P (permutation), L (linear) transformation.
func lps(data [BlockSize]byte) [BlockSize]byte {
	// S + P combined.
	var sp [BlockSize]byte
	for i := 0; i < BlockSize; i++ {
		sp[tau[i]] = pi[data[i]]
	}
	// L transformation using precomputed cache.
	var out [BlockSize]byte
	for i := 0; i < 8; i++ {
		var r uint64
		r ^= cache[0][sp[8*i+0]]
		r ^= cache[1][sp[8*i+1]]
		r ^= cache[2][sp[8*i+2]]
		r ^= cache[3][sp[8*i+3]]
		r ^= cache[4][sp[8*i+4]]
		r ^= cache[5][sp[8*i+5]]
		r ^= cache[6][sp[8*i+6]]
		r ^= cache[7][sp[8*i+7]]
		binary.LittleEndian.PutUint64(out[i*8:i*8+8], r)
	}
	return out
}
