// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// cfbEncrypter implements cipher.Stream for GOST R 34.13-2015 CFB encryption.
// Supports shift register parameter m >= n (len(iv) >= blockSize).
type cfbEncrypter struct {
	b         cipher.Block
	blockSize int
	reg       []byte // shift register of length m
	out       []byte // current gamma block
	outUsed   int
	feed      []byte // accumulates ciphertext bytes for register feedback
	feedLen   int
}

// NewCFBEncrypter returns a cipher.Stream that encrypts using CFB mode.
// The iv length must be a positive multiple of the block size (parameter m).
func NewCFBEncrypter(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) < bs || len(iv)%bs != 0 {
		panic("gost341315: IV length must be a positive multiple of block size")
	}
	c := &cfbEncrypter{
		b:         b,
		blockSize: bs,
		reg:       make([]byte, len(iv)),
		out:       make([]byte, bs),
		feed:      make([]byte, bs),
		outUsed:   bs,
	}
	copy(c.reg, iv)
	return c
}

func (c *cfbEncrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	n := c.blockSize
	for i := 0; i < len(src); i++ {
		if c.outUsed >= n {
			c.b.Encrypt(c.out, c.reg[:n])
			c.outUsed = 0
		}
		dst[i] = src[i] ^ c.out[c.outUsed]
		c.feed[c.feedLen] = dst[i] // ciphertext feeds back
		c.outUsed++
		c.feedLen++
		if c.feedLen == n {
			// Shift register: R = LSB_{m-n}(R) || feed
			copy(c.reg, c.reg[n:])
			copy(c.reg[len(c.reg)-n:], c.feed)
			c.feedLen = 0
		}
	}
}

// cfbDecrypter implements cipher.Stream for GOST R 34.13-2015 CFB decryption.
type cfbDecrypter struct {
	b         cipher.Block
	blockSize int
	reg       []byte
	out       []byte
	outUsed   int
	feed      []byte // accumulates ciphertext bytes for register feedback
	feedLen   int
}

// NewCFBDecrypter returns a cipher.Stream that decrypts using CFB mode.
// The iv length must be a positive multiple of the block size (parameter m).
func NewCFBDecrypter(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) < bs || len(iv)%bs != 0 {
		panic("gost341315: IV length must be a positive multiple of block size")
	}
	c := &cfbDecrypter{
		b:         b,
		blockSize: bs,
		reg:       make([]byte, len(iv)),
		out:       make([]byte, bs),
		feed:      make([]byte, bs),
		outUsed:   bs,
	}
	copy(c.reg, iv)
	return c
}

func (c *cfbDecrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	n := c.blockSize
	for i := 0; i < len(src); i++ {
		if c.outUsed >= n {
			c.b.Encrypt(c.out, c.reg[:n])
			c.outUsed = 0
		}
		c.feed[c.feedLen] = src[i] // ciphertext feeds back (before decryption)
		dst[i] = src[i] ^ c.out[c.outUsed]
		c.outUsed++
		c.feedLen++
		if c.feedLen == n {
			copy(c.reg, c.reg[n:])
			copy(c.reg[len(c.reg)-n:], c.feed)
			c.feedLen = 0
		}
	}
}
