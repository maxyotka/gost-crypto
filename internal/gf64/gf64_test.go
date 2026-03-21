// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gf64

import (
	"testing"
)

func TestMul_ZeroByAnything(t *testing.T) {
	var zero, x [8]byte
	x[0] = 0x42
	x[7] = 0x01

	got := Mul(&zero, &x)
	if got != zero {
		t.Fatalf("0 * x = %x, want 0", got)
	}

	got = Mul(&x, &zero)
	if got != zero {
		t.Fatalf("x * 0 = %x, want 0", got)
	}
}

func TestMul_OneTimesX(t *testing.T) {
	// The identity element in GF(2^64) is the element with only the
	// least significant bit set. In big-endian byte order, that is byte[7] = 0x01.
	var one, x [8]byte
	one[7] = 0x01
	x[0] = 0xab
	x[3] = 0xcd
	x[4] = 0xef
	x[7] = 0x42

	got := Mul(&one, &x)
	if got != x {
		t.Fatalf("1 * x = %x, want %x", got, x)
	}

	got = Mul(&x, &one)
	if got != x {
		t.Fatalf("x * 1 = %x, want %x", got, x)
	}
}

func TestMul_Commutative(t *testing.T) {
	var a, b [8]byte
	a[0] = 0x01
	a[7] = 0x1b
	b[0] = 0xff
	b[4] = 0xaa

	ab := Mul(&a, &b)
	ba := Mul(&b, &a)
	if ab != ba {
		t.Fatalf("a*b = %x, b*a = %x — not commutative", ab, ba)
	}
}

func TestMul_Associative(t *testing.T) {
	var a, b, c [8]byte
	a[7] = 0x03
	b[7] = 0x05
	c[7] = 0x07

	// (a*b)*c
	ab := Mul(&a, &b)
	abc1 := Mul(&ab, &c)

	// a*(b*c)
	bc := Mul(&b, &c)
	abc2 := Mul(&a, &bc)

	if abc1 != abc2 {
		t.Fatalf("(a*b)*c = %x, a*(b*c) = %x — not associative", abc1, abc2)
	}
}

func TestMul_SelfSquare(t *testing.T) {
	// alpha^2 should equal 0x04 (no reduction since degree < 64).
	var x [8]byte
	x[7] = 0x02 // alpha

	got := Mul(&x, &x)
	var want [8]byte
	want[7] = 0x04
	if got != want {
		t.Fatalf("alpha^2 = %x, want %x", got, want)
	}
}

func TestMul_Reduction(t *testing.T) {
	// Multiplying alpha^63 (top bit set) by alpha should trigger reduction.
	// alpha^63 is byte[0] = 0x80, rest zeros.
	// alpha^64 = x^4 + x^3 + x + 1 = 0x1B in byte[7].
	var alpha63, alpha [8]byte
	alpha63[0] = 0x80
	alpha[7] = 0x02

	got := Mul(&alpha63, &alpha)
	var want [8]byte
	want[7] = polynomial // 0x1B
	if got != want {
		t.Fatalf("alpha^63 * alpha = %x, want %x", got, want)
	}
}

func TestMul_KnownVector(t *testing.T) {
	// alpha^2 * alpha^3 = alpha^5 = 0x20 (no reduction needed).
	var a, b [8]byte
	a[7] = 0x04 // alpha^2
	b[7] = 0x08 // alpha^3

	got := Mul(&a, &b)
	var want [8]byte
	want[7] = 0x20 // alpha^5
	if got != want {
		t.Fatalf("alpha^2 * alpha^3 = %x, want %x", got, want)
	}
}

func TestMul_Distributive(t *testing.T) {
	// a * (b XOR c) == (a * b) XOR (a * c)
	var a, b, c [8]byte
	a[7] = 0x03
	b[7] = 0x05
	c[7] = 0x09

	var bc [8]byte
	for i := range bc {
		bc[i] = b[i] ^ c[i]
	}

	lhs := Mul(&a, &bc)

	ab := Mul(&a, &b)
	ac := Mul(&a, &c)
	var rhs [8]byte
	for i := range rhs {
		rhs[i] = ab[i] ^ ac[i]
	}

	if lhs != rhs {
		t.Fatalf("distributive law failed: a*(b^c) = %x, a*b ^ a*c = %x", lhs, rhs)
	}
}
