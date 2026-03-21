// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

// KDF256 derives a 32-byte key using HMAC-Stribog-256 as specified in
// R 50.1.113-2016 (KDF_GOSTR3411_2012_256).
//
// The derivation formula is:
//
//	KDF(key, label, seed) = HMAC-256(key, 0x01 || label || 0x00 || seed || 0x01 || 0x00)
func KDF256(key, label, seed []byte) []byte {
	h := NewHMAC256(key)

	// 0x01 || label || 0x00 || seed || 0x01 || 0x00
	h.Write([]byte{0x01})
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(seed)
	h.Write([]byte{0x01, 0x00})

	return h.Sum(nil)
}
