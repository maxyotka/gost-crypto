// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// WrapKey wraps a content encryption key (CEK) using a key encryption key (KEK).
//
// The algorithm follows RFC 4357 / TK-26 key export:
//  1. Compute a 4-byte MAC of the CEK using CMAC, truncated to 4 bytes.
//  2. Encrypt the CEK using the KEK in ECB mode.
//  3. Return mac(4) || encrypted_cek.
//
// The CEK length must be a multiple of the KEK block size.
func WrapKey(kek cipher.Block, cek []byte) ([]byte, error) {
	bs := kek.BlockSize()
	if len(cek) == 0 || len(cek)%bs != 0 {
		return nil, errors.New("kdf: CEK length must be a positive multiple of block size")
	}

	// Step 1: Compute 4-byte MAC over the plaintext CEK.
	mac := NewCMAC(kek)
	mac.Write(cek)
	tag := mac.Sum(nil)[:4]

	// Step 2: Encrypt CEK in ECB mode.
	encrypted := make([]byte, len(cek))
	for i := 0; i < len(cek); i += bs {
		kek.Encrypt(encrypted[i:i+bs], cek[i:i+bs])
	}

	// Step 3: Prepend MAC to encrypted CEK.
	result := make([]byte, 4+len(encrypted))
	copy(result[:4], tag)
	copy(result[4:], encrypted)

	return result, nil
}

// UnwrapKey unwraps a key that was wrapped with WrapKey.
//
// It decrypts the CEK and verifies the 4-byte MAC prefix.
func UnwrapKey(kek cipher.Block, wrapped []byte) ([]byte, error) {
	bs := kek.BlockSize()
	if len(wrapped) < 4+bs {
		return nil, errors.New("kdf: wrapped key too short")
	}
	encLen := len(wrapped) - 4
	if encLen%bs != 0 {
		return nil, errors.New("kdf: invalid wrapped key length")
	}

	storedMAC := wrapped[:4]
	encrypted := wrapped[4:]

	// Step 1: Decrypt CEK in ECB mode.
	cek := make([]byte, encLen)
	for i := 0; i < encLen; i += bs {
		kek.Decrypt(cek[i:i+bs], encrypted[i:i+bs])
	}

	// Step 2: Recompute MAC and verify.
	mac := NewCMAC(kek)
	mac.Write(cek)
	computedMAC := mac.Sum(nil)[:4]

	if subtle.ConstantTimeCompare(storedMAC, computedMAC) != 1 {
		// Zeroize decrypted CEK on failure.
		for i := range cek {
			cek[i] = 0
		}
		return nil, errors.New("kdf: key unwrap MAC verification failed")
	}

	return cek, nil
}
