// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// cbcEncrypter implements cipher.BlockMode for CBC encryption.
type cbcEncrypter struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

// NewCBCEncrypter returns a cipher.BlockMode which encrypts in CBC mode.
// The iv length must equal the block size.
func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	ivCopy := make([]byte, bs)
	copy(ivCopy, iv)
	return &cbcEncrypter{b: b, blockSize: bs, iv: ivCopy}
}

func (c *cbcEncrypter) BlockSize() int { return c.blockSize }

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}

	prev := c.iv
	for len(src) > 0 {
		// XOR plaintext block with previous ciphertext (or IV).
		xorBytes(dst[:c.blockSize], src[:c.blockSize], prev)
		c.b.Encrypt(dst[:c.blockSize], dst[:c.blockSize])
		prev = dst[:c.blockSize]
		src = src[c.blockSize:]
		dst = dst[c.blockSize:]
	}
	// Save the last ciphertext block as IV for chained CryptBlocks calls.
	copy(c.iv, prev)
}

// cbcDecrypter implements cipher.BlockMode for CBC decryption.
type cbcDecrypter struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in CBC mode.
// The iv length must equal the block size.
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	ivCopy := make([]byte, bs)
	copy(ivCopy, iv)
	return &cbcDecrypter{b: b, blockSize: bs, iv: ivCopy}
}

func (c *cbcDecrypter) BlockSize() int { return c.blockSize }

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%c.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}

	// Save last ciphertext block as the new IV before processing,
	// in case dst and src overlap (in-place decryption).
	newIV := make([]byte, c.blockSize)
	copy(newIV, src[len(src)-c.blockSize:])

	// Process blocks from the end to support in-place decryption (dst == src).
	end := len(src)
	for end > 0 {
		start := end - c.blockSize
		var prev []byte
		if start == 0 {
			prev = c.iv
		} else {
			prev = src[start-c.blockSize : start]
		}
		c.b.Decrypt(dst[start:end], src[start:end])
		xorBytes(dst[start:end], dst[start:end], prev)
		end = start
	}

	// Update IV for chained CryptBlocks calls.
	copy(c.iv, newIV)
}
