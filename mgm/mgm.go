// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package mgm implements the Multilinear Galois Mode (MGM) authenticated
// encryption with associated data (AEAD) as defined in RFC 9058.
//
// MGM can be used with any block cipher that has a block size of 64 or 128
// bits. It is designed for use with the GOST block ciphers Kuznyechik
// (128-bit) and Magma (64-bit) from GOST R 34.12-2015.
package mgm

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/maxyotka/gost-crypto/internal/gf128"
	"github.com/maxyotka/gost-crypto/internal/gf64"
)

// mgm implements cipher.AEAD for MGM mode.
type mgm struct {
	cipher    cipher.Block
	blockSize int
	tagSize   int
}

// NewMGM creates a new MGM AEAD from the given block cipher.
// The tagSize must be between blockSize/2 and blockSize (inclusive).
// The block cipher must have a block size of 8 (Magma) or 16 (Kuznechik).
func NewMGM(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	bs := block.BlockSize()
	if bs != 8 && bs != 16 {
		return nil, errors.New("mgm: block size must be 8 or 16")
	}
	if tagSize < bs/2 || tagSize > bs {
		return nil, errors.New("mgm: invalid tag size")
	}
	return &mgm{
		cipher:    block,
		blockSize: bs,
		tagSize:   tagSize,
	}, nil
}

// NonceSize returns the nonce size, which equals the block size.
func (m *mgm) NonceSize() int { return m.blockSize }

// Overhead returns the maximum overhead (tag size).
func (m *mgm) Overhead() int { return m.tagSize }

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the
// updated slice.
func (m *mgm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != m.blockSize {
		panic("mgm: incorrect nonce length")
	}
	// Nonce MSB must be 0 (per RFC 9058).
	if nonce[0]&0x80 != 0 {
		panic("mgm: nonce MSB must be zero")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+m.tagSize)

	ciphertext := out[:len(plaintext)]
	tag := out[len(plaintext):]

	m.deriveAndProcess(nonce, plaintext, additionalData, ciphertext, tag, true)
	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and appends the resulting plaintext to dst.
func (m *mgm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != m.blockSize {
		return nil, errors.New("mgm: incorrect nonce length")
	}
	if len(ciphertext) < m.tagSize {
		return nil, errors.New("mgm: ciphertext too short")
	}

	ct := ciphertext[:len(ciphertext)-m.tagSize]
	expectedTag := ciphertext[len(ciphertext)-m.tagSize:]

	ret, out := sliceForAppend(dst, len(ct))

	var computedTag [16]byte // large enough for both block sizes

	m.deriveAndProcess(nonce, ct, additionalData, out, computedTag[:m.tagSize], false)

	if subtle.ConstantTimeCompare(computedTag[:m.tagSize], expectedTag) != 1 {
		// Zero out plaintext on authentication failure.
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("mgm: authentication failed")
	}

	return ret, nil
}

// deriveAndProcess performs the core MGM encryption/decryption and tag computation.
// When encrypting, data is the plaintext and result is the ciphertext.
// When decrypting, data is the ciphertext and result is the plaintext.
//
// Per RFC 9058:
//   - Y_1 = E_K(0^1 || ICN), subsequent Y_i = incr_r(Y_{i-1})
//   - Z_1 = E_K(1^1 || ICN), subsequent Z_i = incr_l(Z_{i-1})
//   - H_i = E_K(Z_i)
//   - sum = XOR of H_i * A_i (for AD blocks) and H_{h+j} * C_j (for CT blocks)
//   - T = MSB_S(E_K(sum XOR (H_{h+q+1} * (len(A) || len(C)))))
func (m *mgm) deriveAndProcess(nonce, data, ad []byte, result, tag []byte, encrypting bool) {
	bs := m.blockSize
	half := bs / 2

	// Y_1 = E_K(0^1 || ICN): encryption counter initial value.
	// The MSB of ICN is already 0 (checked in Seal).
	encInput := make([]byte, bs)
	copy(encInput, nonce)
	encInput[0] &= 0x7F // clear MSB

	y := make([]byte, bs)
	m.cipher.Encrypt(y, encInput)

	// Z_1 = E_K(1^1 || ICN): authentication counter initial value.
	authInput := make([]byte, bs)
	copy(authInput, nonce)
	authInput[0] |= 0x80 // set MSB

	z := make([]byte, bs)
	m.cipher.Encrypt(z, authInput)

	// Authentication accumulator (sum = 0^n).
	authAccum := make([]byte, bs)

	// Process additional data blocks for authentication.
	adLen := len(ad)
	for off := 0; off < adLen; off += bs {
		// H_i = E_K(Z_i)
		hi := make([]byte, bs)
		m.cipher.Encrypt(hi, z)

		end := off + bs
		var adBlock []byte
		if end <= adLen {
			adBlock = ad[off:end]
		} else {
			// Pad the last block with zeros.
			tmp := make([]byte, bs)
			copy(tmp, ad[off:])
			adBlock = tmp
		}

		// sum ^= H_i * A_i
		m.mulXOR(authAccum, hi, adBlock)

		// Z_{i+1} = incr_l(Z_i)
		incrLeft(z, half)
	}

	// Process data (encrypt or decrypt) and authenticate ciphertext.
	dataLen := len(data)
	for off := 0; off < dataLen; off += bs {
		// Generate encryption keystream: E_K(Y_i)
		eY := make([]byte, bs)
		m.cipher.Encrypt(eY, y)

		end := off + bs
		if end > dataLen {
			end = dataLen
		}
		chunkSize := end - off

		// XOR data with keystream to produce result.
		for i := 0; i < chunkSize; i++ {
			result[off+i] = data[off+i] ^ eY[i]
		}

		// For authentication we need the ciphertext block.
		var ctBlock []byte
		if encrypting {
			ctBlock = result[off:end]
		} else {
			ctBlock = data[off:end]
		}

		// H_i = E_K(Z_i)
		hi := make([]byte, bs)
		m.cipher.Encrypt(hi, z)

		// Pad the last CT block if needed.
		if chunkSize < bs {
			tmp := make([]byte, bs)
			copy(tmp, ctBlock)
			ctBlock = tmp
		}

		// sum ^= H_i * C_j
		m.mulXOR(authAccum, hi, ctBlock)

		// Y_{i+1} = incr_r(Y_i), Z_{i+1} = incr_l(Z_i)
		incrRight(y, half)
		incrLeft(z, half)
	}

	// Final tag computation.
	// lenBlock = len(A) || len(C) in bits, encoded as big-endian.
	lenBlock := make([]byte, bs)
	adBits := uint64(adLen) * 8
	ctBits := uint64(dataLen) * 8

	if bs == 16 {
		putUint64BE(lenBlock[0:8], adBits)
		putUint64BE(lenBlock[8:16], ctBits)
	} else {
		putUint32BE(lenBlock[0:4], uint32(adBits))
		putUint32BE(lenBlock[4:8], uint32(ctBits))
	}

	// H_{h+q+1} = E_K(Z_{h+q+1})
	hFinal := make([]byte, bs)
	m.cipher.Encrypt(hFinal, z)

	// T = MSB_S(E_K(sum XOR (H_{h+q+1} * lenBlock)))
	m.mulXOR(authAccum, hFinal, lenBlock)

	fullTag := make([]byte, bs)
	m.cipher.Encrypt(fullTag, authAccum)
	copy(tag, fullTag[:m.tagSize])

	// Zeroize sensitive intermediate state.
	for i := range y {
		y[i] = 0
	}
	for i := range z {
		z[i] = 0
	}
	for i := range authAccum {
		authAccum[i] = 0
	}
	for i := range fullTag {
		fullTag[i] = 0
	}
}

// mulXOR computes accum ^= gfMul(a, b) using the appropriate field
// based on the block size.
func (m *mgm) mulXOR(accum, a, b []byte) {
	if m.blockSize == 16 {
		var aa, bb [16]byte
		copy(aa[:], a)
		copy(bb[:], b)
		product := gf128.Mul(&aa, &bb)
		for i := 0; i < 16; i++ {
			accum[i] ^= product[i]
		}
	} else {
		var aa, bb [8]byte
		copy(aa[:], a)
		copy(bb[:], b)
		product := gf64.Mul(&aa, &bb)
		for i := 0; i < 8; i++ {
			accum[i] ^= product[i]
		}
	}
}

// incrLeft increments the left half of a block as a big-endian integer mod 2^(half*8).
// This corresponds to incr_l from RFC 9058.
func incrLeft(block []byte, half int) {
	for i := half - 1; i >= 0; i-- {
		block[i]++
		if block[i] != 0 {
			break
		}
	}
}

// incrRight increments the right half of a block as a big-endian integer mod 2^(half*8).
// This corresponds to incr_r from RFC 9058.
func incrRight(block []byte, half int) {
	n := len(block)
	for i := n - 1; i >= half; i-- {
		block[i]++
		if block[i] != 0 {
			break
		}
	}
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by the requested number
// of bytes and a second slice that aliases into it and contains only the
// requested new bytes.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func putUint64BE(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
