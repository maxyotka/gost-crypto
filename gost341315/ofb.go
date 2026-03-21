// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// ofb implements cipher.Stream for OFB mode.
type ofb struct {
	b         cipher.Block
	blockSize int
	out       []byte // current feedback block (encrypted output)
	outUsed   int    // how many bytes of out have been consumed
}

// NewOFB returns a cipher.Stream that encrypts/decrypts using OFB mode.
// The iv length must equal the block size.
func NewOFB(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("gost341315: IV length must equal block size")
	}
	o := &ofb{
		b:         b,
		blockSize: bs,
		out:       make([]byte, bs),
		outUsed:   bs, // force generation on first use
	}
	copy(o.out, iv)
	return o
}

func (o *ofb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		if o.outUsed >= o.blockSize {
			// Encrypt the current feedback to produce the next keystream block.
			o.b.Encrypt(o.out, o.out)
			o.outUsed = 0
		}
		n := len(src)
		if avail := o.blockSize - o.outUsed; n > avail {
			n = avail
		}
		xorBytes(dst[:n], src[:n], o.out[o.outUsed:o.outUsed+n])
		o.outUsed += n
		src = src[n:]
		dst = dst[n:]
	}
}
