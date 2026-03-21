// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

import (
	"crypto/cipher"
	"hash"
)

// cmac implements hash.Hash for CMAC (OMAC1) as defined in
// NIST SP 800-38B and ГОСТ Р 34.13-2015, Section 5.6.
type cmac struct {
	b         cipher.Block
	blockSize int
	k1, k2   []byte // derived subkeys
	x         []byte // running CBC-MAC state
	buf       []byte // unprocessed bytes
	bufLen    int
}

// NewCMAC creates a CMAC hash.Hash based on the provided cipher.Block.
// The tag size equals the cipher block size.
func NewCMAC(b cipher.Block) hash.Hash {
	bs := b.BlockSize()
	m := &cmac{
		b:         b,
		blockSize: bs,
		k1:        make([]byte, bs),
		k2:        make([]byte, bs),
		x:         make([]byte, bs),
		buf:       make([]byte, bs),
	}
	m.deriveSubkeys()
	return m
}

// deriveSubkeys computes CMAC subkeys K1 and K2.
//
//	L = E_K(0^n)
//	K1 = dbl(L)
//	K2 = dbl(K1)
func (m *cmac) deriveSubkeys() {
	l := make([]byte, m.blockSize)
	m.b.Encrypt(l, l)

	var rb byte
	switch m.blockSize {
	case 16:
		rb = 0x87 // GF(2^128)
	case 8:
		rb = 0x1B // GF(2^64)
	default:
		panic("kdf: unsupported block size for CMAC")
	}

	m.k1 = cmacDbl(l, rb)
	m.k2 = cmacDbl(m.k1, rb)
}

// cmacDbl performs the doubling operation in GF(2^n).
func cmacDbl(data []byte, rb byte) []byte {
	n := len(data)
	result := make([]byte, n)
	carry := data[0] >> 7

	for i := 0; i < n-1; i++ {
		result[i] = (data[i] << 1) | (data[i+1] >> 7)
	}
	result[n-1] = data[n-1] << 1

	if carry == 1 {
		result[n-1] ^= rb
	}
	return result
}

func (m *cmac) Write(p []byte) (n int, err error) {
	n = len(p)

	if m.bufLen > 0 {
		space := m.blockSize - m.bufLen
		if len(p) <= space {
			copy(m.buf[m.bufLen:], p)
			m.bufLen += len(p)
			return
		}
		copy(m.buf[m.bufLen:], p[:space])
		m.bufLen = m.blockSize
		p = p[space:]
		if len(p) > 0 {
			xorBlock(m.x, m.buf[:m.blockSize])
			m.b.Encrypt(m.x, m.x)
			m.bufLen = 0
		}
	}

	for len(p) > m.blockSize {
		xorBlock(m.x, p[:m.blockSize])
		m.b.Encrypt(m.x, m.x)
		p = p[m.blockSize:]
	}

	if len(p) > 0 {
		if m.bufLen > 0 {
			xorBlock(m.x, m.buf[:m.blockSize])
			m.b.Encrypt(m.x, m.x)
			m.bufLen = 0
		}
		copy(m.buf, p)
		m.bufLen = len(p)
	}
	return
}

func (m *cmac) Sum(in []byte) []byte {
	x := make([]byte, m.blockSize)
	copy(x, m.x)

	var lastBlock []byte
	if m.bufLen == m.blockSize {
		lastBlock = make([]byte, m.blockSize)
		for i := 0; i < m.blockSize; i++ {
			lastBlock[i] = m.buf[i] ^ m.k1[i]
		}
	} else {
		padded := make([]byte, m.blockSize)
		copy(padded, m.buf[:m.bufLen])
		padded[m.bufLen] = 0x80
		lastBlock = make([]byte, m.blockSize)
		for i := 0; i < m.blockSize; i++ {
			lastBlock[i] = padded[i] ^ m.k2[i]
		}
	}

	for i := 0; i < m.blockSize; i++ {
		x[i] ^= lastBlock[i]
	}
	m.b.Encrypt(x, x)

	return append(in, x...)
}

func (m *cmac) Reset() {
	for i := range m.x {
		m.x[i] = 0
	}
	m.bufLen = 0
}

func (m *cmac) Size() int      { return m.blockSize }
func (m *cmac) BlockSize() int { return m.blockSize }

// xorBlock XORs src into dst in-place. Both must be the same length.
func xorBlock(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
