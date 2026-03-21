// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// ctr implements cipher.Stream for GOST CTR mode.
// Per GOST R 34.13-2015, the counter is incremented as a big-endian integer
// in the right half of the IV block. The left half stays constant.
type ctr struct {
	b         cipher.Block
	blockSize int
	ctr       []byte // current counter block (full block size)
	out       []byte // encrypted counter output (keystream)
	outUsed   int    // how many bytes of out have been consumed
}

// NewCTR returns a cipher.Stream that encrypts/decrypts using GOST CTR mode.
// The iv length must equal the block size.
func NewCTR(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	c := &ctr{
		b:         b,
		blockSize: bs,
		ctr:       make([]byte, bs),
		out:       make([]byte, bs),
		outUsed:   bs, // force generation on first use
	}
	copy(c.ctr, iv)
	return c
}

func (c *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		if c.outUsed >= c.blockSize {
			// Encrypt the current counter to produce keystream.
			c.b.Encrypt(c.out, c.ctr)
			c.outUsed = 0
			// Increment the right half of the counter as a big-endian integer.
			c.incCounter()
		}
		n := len(src)
		if avail := c.blockSize - c.outUsed; n > avail {
			n = avail
		}
		xorBytes(dst[:n], src[:n], c.out[c.outUsed:c.outUsed+n])
		c.outUsed += n
		src = src[n:]
		dst = dst[n:]
	}
}

// incCounter increments the right half of the counter block as a big-endian
// integer. The right half is bytes [blockSize/2 : blockSize].
func (c *ctr) incCounter() {
	half := c.blockSize / 2
	// Increment the right half as a big-endian integer with carry.
	for i := c.blockSize - 1; i >= half; i-- {
		c.ctr[i]++
		if c.ctr[i] != 0 {
			break
		}
	}
}
