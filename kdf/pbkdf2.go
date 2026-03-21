// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// PBKDF2 derives a key of length keyLen bytes from the given password and salt
// using iter iterations of the HMAC-based pseudorandom function constructed
// from h. This implements PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0.
//
// Typical usage with Stribog-256:
//
//	dk := kdf.PBKDF2([]byte("password"), salt, 4096, 32, gost341112.New256)
func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)

	var block [4]byte
	for i := 1; i <= numBlocks; i++ {
		// U_1 = PRF(password, salt || INT_32_BE(i))
		binary.BigEndian.PutUint32(block[:], uint32(i))

		prf.Reset()
		prf.Write(salt)
		prf.Write(block[:])
		u := prf.Sum(nil)

		// T_i = U_1 XOR U_2 XOR ... XOR U_iter
		t := make([]byte, hashLen)
		copy(t, u)

		for j := 2; j <= iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])

			for k := 0; k < hashLen; k++ {
				t[k] ^= u[k]
			}
		}

		dk = append(dk, t...)
	}

	return dk[:keyLen]
}
