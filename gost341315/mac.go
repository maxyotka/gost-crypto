// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import (
	"crypto/cipher"
	"errors"
	"hash"
)

// cmac implements hash.Hash for CMAC-based MAC per GOST R 34.13-2015.
type cmac struct {
	b         cipher.Block
	blockSize int
	macSize   int
	k1, k2   []byte // derived subkeys
	x         []byte // running CBC-MAC state
	buf       []byte // unprocessed bytes
	bufLen    int
}

// NewMAC returns a hash.Hash that computes CMAC using the given block cipher.
// macSize specifies the desired MAC tag length in bytes and must be between
// 1 and b.BlockSize() inclusive.
func NewMAC(b cipher.Block, macSize int) (hash.Hash, error) {
	bs := b.BlockSize()
	if macSize < 1 || macSize > bs {
		return nil, errors.New("gost341315: invalid MAC size")
	}

	m := &cmac{
		b:         b,
		blockSize: bs,
		macSize:   macSize,
		k1:        make([]byte, bs),
		k2:        make([]byte, bs),
		x:         make([]byte, bs),
		buf:       make([]byte, bs),
	}
	m.deriveSubkeys()
	return m, nil
}

// deriveSubkeys computes the CMAC subkeys K1 and K2.
// K1 = L << 1 if MSB(L)=0, else (L << 1) XOR Rb
// K2 = K1 << 1 if MSB(K1)=0, else (K1 << 1) XOR Rb
// where L = E_K(0^n) and Rb is the reduction polynomial constant.
func (m *cmac) deriveSubkeys() {
	// L = E_K(0^n)
	l := make([]byte, m.blockSize)
	m.b.Encrypt(l, l)

	// Determine the reduction polynomial Rb based on block size.
	var rb byte
	switch m.blockSize {
	case 16:
		// GF(2^128): x^128 + x^7 + x^2 + x + 1 => Rb = 0x87
		rb = 0x87
	case 8:
		// GF(2^64): x^64 + x^4 + x^3 + x + 1 => Rb = 0x1B
		rb = 0x1B
	default:
		panic("gost341315: unsupported block size for MAC")
	}

	// K1 = dbl(L)
	m.k1 = dbl(l, rb)
	// K2 = dbl(K1)
	m.k2 = dbl(m.k1, rb)
}

// dbl performs the doubling operation (left shift by 1 with conditional XOR).
func dbl(data []byte, rb byte) []byte {
	n := len(data)
	result := make([]byte, n)
	carry := data[0] >> 7 // MSB

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
	// If we have buffered data, try to fill the buffer first.
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
		// Process the full buffer, but only if there's more data coming.
		// We must keep the last block for finalization.
		if len(p) > 0 {
			xorBytes(m.x, m.x, m.buf[:m.blockSize])
			m.b.Encrypt(m.x, m.x)
			m.bufLen = 0
		}
	}

	// Process full blocks, but always keep the last block buffered.
	for len(p) > m.blockSize {
		xorBytes(m.x, m.x, p[:m.blockSize])
		m.b.Encrypt(m.x, m.x)
		p = p[m.blockSize:]
	}

	// Buffer remaining bytes (bufLen is always 0 here).
	if len(p) > 0 {
		copy(m.buf, p)
		m.bufLen = len(p)
	}
	return
}

func (m *cmac) Sum(in []byte) []byte {
	// Make a copy of state so Sum doesn't modify the hasher.
	x := make([]byte, m.blockSize)
	copy(x, m.x)
	buf := make([]byte, m.blockSize)
	copy(buf, m.buf[:m.bufLen])
	bufLen := m.bufLen

	var lastBlock []byte
	if bufLen == m.blockSize {
		// Complete block: XOR with K1.
		lastBlock = make([]byte, m.blockSize)
		xorBytes(lastBlock, buf, m.k1)
	} else {
		// Incomplete block: pad with 1||0...0 and XOR with K2.
		padded := make([]byte, m.blockSize)
		copy(padded, buf[:bufLen])
		padded[bufLen] = 0x80
		lastBlock = make([]byte, m.blockSize)
		xorBytes(lastBlock, padded, m.k2)
	}

	xorBytes(x, x, lastBlock)
	m.b.Encrypt(x, x)

	return append(in, x[:m.macSize]...)
}

func (m *cmac) Reset() {
	for i := range m.x {
		m.x[i] = 0
	}
	m.bufLen = 0
}

func (m *cmac) Size() int { return m.macSize }

func (m *cmac) BlockSize() int { return m.blockSize }
