// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341112

// init performs a self-test using the empty-message KAT from RFC 6986.
// Panics if the computed hash does not match the expected value.
func init() {
	// Stribog-256("") = 3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb
	expected := [Size256]byte{
		0x3f, 0x53, 0x9a, 0x21, 0x3e, 0x97, 0xc8, 0x02,
		0xcc, 0x22, 0x9d, 0x47, 0x4c, 0x6a, 0xa3, 0x2a,
		0x82, 0x5a, 0x36, 0x0b, 0x2a, 0x93, 0x3a, 0x94,
		0x9f, 0xd9, 0x25, 0x20, 0x8d, 0x9c, 0xe1, 0xbb,
	}
	h := New256()
	got := h.Sum(nil)
	for i := range expected {
		if got[i] != expected[i] {
			panic("gost341112: self-test failed — Stribog-256 KAT mismatch")
		}
	}
}
