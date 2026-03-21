// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import "crypto/cipher"

// ofb implements cipher.Stream for GOST R 34.13-2015 OFB mode.
// Supports shift register parameter m >= n (len(iv) >= blockSize).
type ofb struct {
	b         cipher.Block
	blockSize int
	reg       []byte // shift register of length m
	out       []byte // current keystream block
	outUsed   int
}

// NewOFB returns a cipher.Stream that encrypts/decrypts using OFB mode.
// The iv length must be a positive multiple of the block size (parameter m).
func NewOFB(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) < bs || len(iv)%bs != 0 {
		panic("gost341315: IV length must be a positive multiple of block size")
	}
	o := &ofb{
		b:         b,
		blockSize: bs,
		reg:       make([]byte, len(iv)),
		out:       make([]byte, bs),
		outUsed:   bs, // force generation on first use
	}
	copy(o.reg, iv)
	return o
}

func (o *ofb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	n := o.blockSize
	for len(src) > 0 {
		if o.outUsed >= n {
			// Encrypt MSB_n(R) to produce keystream block.
			o.b.Encrypt(o.out, o.reg[:n])
			o.outUsed = 0

			// Shift register: R = LSB_{m-n}(R) || output
			copy(o.reg, o.reg[n:])
			copy(o.reg[len(o.reg)-n:], o.out)
		}
		avail := n - o.outUsed
		if avail > len(src) {
			avail = len(src)
		}
		xorBytes(dst[:avail], src[:avail], o.out[o.outUsed:o.outUsed+avail])
		o.outUsed += avail
		src = src[avail:]
		dst = dst[avail:]
	}
}
