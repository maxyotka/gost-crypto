// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// cfbEncrypter implements cipher.Stream for CFB encryption.
type cfbEncrypter struct {
	b         cipher.Block
	blockSize int
	prev      []byte // previous ciphertext block (or IV)
	out       []byte // encrypted previous block
	outUsed   int    // how many bytes of out have been consumed
}

// NewCFBEncrypter returns a cipher.Stream that encrypts using CFB mode.
// The iv length must equal the block size.
func NewCFBEncrypter(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	c := &cfbEncrypter{
		b:         b,
		blockSize: bs,
		prev:      make([]byte, bs),
		out:       make([]byte, bs),
		outUsed:   bs, // force generation on first use
	}
	copy(c.prev, iv)
	return c
}

func (c *cfbEncrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		if c.outUsed >= c.blockSize {
			c.b.Encrypt(c.out, c.prev)
			c.outUsed = 0
		}
		// Encrypt one byte at a time: ciphertext = plaintext XOR keystream.
		// The ciphertext feeds back into the next block.
		n := len(src)
		if avail := c.blockSize - c.outUsed; n > avail {
			n = avail
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ c.out[c.outUsed+i]
			c.prev[c.outUsed+i] = dst[i]
		}
		c.outUsed += n
		src = src[n:]
		dst = dst[n:]
	}
}

// cfbDecrypter implements cipher.Stream for CFB decryption.
type cfbDecrypter struct {
	b         cipher.Block
	blockSize int
	prev      []byte // previous ciphertext block (or IV)
	out       []byte // encrypted previous block
	outUsed   int    // how many bytes of out have been consumed
}

// NewCFBDecrypter returns a cipher.Stream that decrypts using CFB mode.
// The iv length must equal the block size.
func NewCFBDecrypter(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	c := &cfbDecrypter{
		b:         b,
		blockSize: bs,
		prev:      make([]byte, bs),
		out:       make([]byte, bs),
		outUsed:   bs, // force generation on first use
	}
	copy(c.prev, iv)
	return c
}

func (c *cfbDecrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		if c.outUsed >= c.blockSize {
			c.b.Encrypt(c.out, c.prev)
			c.outUsed = 0
		}
		n := len(src)
		if avail := c.blockSize - c.outUsed; n > avail {
			n = avail
		}
		for i := 0; i < n; i++ {
			// Save ciphertext before overwriting (for feedback).
			c.prev[c.outUsed+i] = src[i]
			dst[i] = src[i] ^ c.out[c.outUsed+i]
		}
		c.outUsed += n
		src = src[n:]
		dst = dst[n:]
	}
}
