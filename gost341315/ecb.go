// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341315 implements block cipher modes of operation
// defined in GOST R 34.13-2015.
package gost341315

import "crypto/cipher"

// ecbEncrypter implements cipher.BlockMode for ECB encryption.
type ecbEncrypter struct {
	b         cipher.Block
	blockSize int
}

// NewECBEncrypter returns a cipher.BlockMode which encrypts in ECB mode.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b: b, blockSize: b.BlockSize()}
}

func (e *ecbEncrypter) BlockSize() int { return e.blockSize }

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		e.b.Encrypt(dst[:e.blockSize], src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

// ecbDecrypter implements cipher.BlockMode for ECB decryption.
type ecbDecrypter struct {
	b         cipher.Block
	blockSize int
}

// NewECBDecrypter returns a cipher.BlockMode which decrypts in ECB mode.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{b: b, blockSize: b.BlockSize()}
}

func (d *ecbDecrypter) BlockSize() int { return d.blockSize }

func (d *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("gost341315: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("gost341315: output smaller than input")
	}
	for len(src) > 0 {
		d.b.Decrypt(dst[:d.blockSize], src[:d.blockSize])
		src = src[d.blockSize:]
		dst = dst[d.blockSize:]
	}
}
