// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// cbcEncrypter implements cipher.BlockMode for GOST R 34.13-2015 CBC mode.
// Supports shift register parameter m >= n (len(iv) >= blockSize).
// When len(iv) == blockSize (m=n), this is standard textbook CBC.
type cbcEncrypter struct {
	b         cipher.Block
	blockSize int
	reg       []byte // shift register of length m
}

// NewCBCEncrypter returns a cipher.BlockMode which encrypts in CBC mode.
// The iv length must be a positive multiple of the block size (parameter m).
// Use len(iv)==blockSize for standard CBC, or larger for GOST m>n mode.
func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	bs := b.BlockSize()
	if len(iv) < bs || len(iv)%bs != 0 {
		panic("gost341315: IV length must be a positive multiple of block size")
	}
	reg := make([]byte, len(iv))
	copy(reg, iv)
	return &cbcEncrypter{b: b, blockSize: bs, reg: reg}
}

func (c *cbcEncrypter) BlockSize() int { return c.blockSize }

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}

	n := c.blockSize
	for len(src) > 0 {
		// Ci = E(Pi XOR MSB_n(R))
		xorBytes(dst[:n], src[:n], c.reg[:n])
		c.b.Encrypt(dst[:n], dst[:n])

		// R = LSB_{m-n}(R) || Ci
		copy(c.reg, c.reg[n:])
		copy(c.reg[len(c.reg)-n:], dst[:n])

		src = src[n:]
		dst = dst[n:]
	}
}

// cbcDecrypter implements cipher.BlockMode for GOST R 34.13-2015 CBC decryption.
type cbcDecrypter struct {
	b         cipher.Block
	blockSize int
	reg       []byte // shift register of length m
}

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in CBC mode.
// The iv length must be a positive multiple of the block size (parameter m).
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	bs := b.BlockSize()
	if len(iv) < bs || len(iv)%bs != 0 {
		panic("gost341315: IV length must be a positive multiple of block size")
	}
	reg := make([]byte, len(iv))
	copy(reg, iv)
	return &cbcDecrypter{b: b, blockSize: bs, reg: reg}
}

func (c *cbcDecrypter) BlockSize() int { return c.blockSize }

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}

	n := c.blockSize
	for len(src) > 0 {
		// Save Ci before potential in-place overwrite.
		var ci [32]byte // max block size
		copy(ci[:n], src[:n])

		// Pi = D(Ci) XOR MSB_n(R)
		c.b.Decrypt(dst[:n], src[:n])
		xorBytes(dst[:n], dst[:n], c.reg[:n])

		// R = LSB_{m-n}(R) || Ci
		copy(c.reg, c.reg[n:])
		copy(c.reg[len(c.reg)-n:], ci[:n])

		src = src[n:]
		dst = dst[n:]
	}
}
