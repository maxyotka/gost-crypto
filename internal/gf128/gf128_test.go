// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gf128

import "testing"

func TestMul_Identity(t *testing.T) {
	one := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	x := [16]byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}

	got := Mul(&x, &one)
	if got != x {
		t.Errorf("x * 1 = %x, want %x", got, x)
	}

	got = Mul(&one, &x)
	if got != x {
		t.Errorf("1 * x = %x, want %x", got, x)
	}
}

func TestMul_Zero(t *testing.T) {
	zero := [16]byte{}
	x := [16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	got := Mul(&x, &zero)
	if got != zero {
		t.Errorf("x * 0 = %x, want %x", got, zero)
	}
}

func TestMul_Commutative(t *testing.T) {
	a := [16]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	b := [16]byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}

	ab := Mul(&a, &b)
	ba := Mul(&b, &a)
	if ab != ba {
		t.Errorf("a*b = %x, b*a = %x — not commutative", ab, ba)
	}
}

func TestMul_AlphaSquared(t *testing.T) {
	// alpha * alpha = alpha^2. No reduction since degree 2 < 128.
	alpha := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	got := Mul(&alpha, &alpha)
	want := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}
	if got != want {
		t.Errorf("alpha^2 = %x, want %x", got, want)
	}
}

func TestMul_Reduction(t *testing.T) {
	// alpha^127 (bit 127 set) * alpha = alpha^128 => reduction.
	// alpha^127 as big-endian uint128: hi=0x8000000000000000, lo=0
	// = byte[0]=0x80, rest zeros.
	// alpha^128 mod (x^128+x^7+x^2+x+1) = x^7+x^2+x+1 = 0x87
	// = byte[15]=0x87
	a := [16]byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	two := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	got := Mul(&a, &two)
	want := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87}
	if got != want {
		t.Errorf("alpha^127 * alpha = %x, want %x", got, want)
	}
}

func TestMul_Associative(t *testing.T) {
	a := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	b := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	c := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}

	ab := Mul(&a, &b)
	abc1 := Mul(&ab, &c)

	bc := Mul(&b, &c)
	abc2 := Mul(&a, &bc)

	if abc1 != abc2 {
		t.Errorf("(a*b)*c = %x, a*(b*c) = %x — not associative", abc1, abc2)
	}
}

func TestMul_Distributive(t *testing.T) {
	a := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	b := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	c := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}

	var bc [16]byte
	for i := range bc {
		bc[i] = b[i] ^ c[i]
	}

	lhs := Mul(&a, &bc)

	ab := Mul(&a, &b)
	ac := Mul(&a, &c)
	var rhs [16]byte
	for i := range rhs {
		rhs[i] = ab[i] ^ ac[i]
	}

	if lhs != rhs {
		t.Errorf("distributive law failed: a*(b^c) = %x, a*b ^ a*c = %x", lhs, rhs)
	}
}

func BenchmarkMul(b *testing.B) {
	x := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	y := [16]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	for i := 0; i < b.N; i++ {
		Mul(&x, &y)
	}
}
