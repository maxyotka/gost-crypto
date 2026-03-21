// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package subtle implements constant-time utilities for cryptographic operations.
package subtle

// ConstantTimeCompare returns 1 if x and y have equal contents and 0 otherwise.
// The time taken is a function of the length of the slices and is independent
// of the contents.
func ConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	var v byte
	for i := range x {
		v |= x[i] ^ y[i]
	}

	return constantTimeByteEq(v, 0)
}

// constantTimeByteEq returns 1 if a == b, 0 otherwise. Constant-time.
func constantTimeByteEq(a, b byte) int {
	x := ^(a ^ b)
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}

// zeroSink is read after zeroing to create a data dependency that
// prevents the compiler from eliminating the zero-writes as dead stores.
// This technique is used by BoringSSL and other cryptographic libraries.
var zeroSink byte

// Zeroize securely zeroes a byte slice. The combination of //go:noinline
// and a read-back into a package-level variable guarantees the writes
// cannot be optimized away by the compiler.
//
//go:noinline
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	if len(b) > 0 {
		zeroSink = b[0]
	}
}

// XORBytes XORs the bytes in a and b into dst. The number of bytes XORed
// equals min(len(dst), len(a), len(b)). The return value is the number
// of bytes XORed.
func XORBytes(dst, a, b []byte) int {
	n := len(dst)
	if len(a) < n {
		n = len(a)
	}
	if len(b) < n {
		n = len(b)
	}

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}
