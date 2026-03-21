// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package kdf implements key derivation functions and related primitives
// based on GOST cryptographic algorithms:
//   - HMAC-Stribog-256/512
//   - KDF per R 50.1.113-2016
//   - PBKDF2 per RFC 2898
//   - CMAC (OMAC1)
//   - GOST key wrap
package kdf

import (
	"crypto/hmac"
	"hash"

	"github.com/maxyotka/gost-crypto/gost341112"
)

// NewHMAC256 returns a new HMAC-Stribog-256 hash.Hash keyed with the given key.
func NewHMAC256(key []byte) hash.Hash {
	return hmac.New(gost341112.New256, key)
}

// NewHMAC512 returns a new HMAC-Stribog-512 hash.Hash keyed with the given key.
func NewHMAC512(key []byte) hash.Hash {
	return hmac.New(gost341112.New512, key)
}
