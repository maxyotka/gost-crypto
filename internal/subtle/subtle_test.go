// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package subtle

import (
	"bytes"
	"testing"
)

// ---------- ConstantTimeCompare ----------

func TestConstantTimeCompare_Equal(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	if got := ConstantTimeCompare(a, b); got != 1 {
		t.Errorf("expected 1 for equal slices, got %d", got)
	}
}

func TestConstantTimeCompare_NotEqual(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04}
	b := []byte{0x01, 0x02, 0x03, 0x05}
	if got := ConstantTimeCompare(a, b); got != 0 {
		t.Errorf("expected 0 for different slices, got %d", got)
	}
}

func TestConstantTimeCompare_DifferentLength(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	if got := ConstantTimeCompare(a, b); got != 0 {
		t.Errorf("expected 0 for different-length slices, got %d", got)
	}
}

func TestConstantTimeCompare_Empty(t *testing.T) {
	if got := ConstantTimeCompare(nil, nil); got != 1 {
		t.Errorf("expected 1 for two nil slices, got %d", got)
	}
	if got := ConstantTimeCompare([]byte{}, []byte{}); got != 1 {
		t.Errorf("expected 1 for two empty slices, got %d", got)
	}
}

func TestConstantTimeCompare_SingleByteDifference(t *testing.T) {
	a := []byte{0xff}
	b := []byte{0x00}
	if got := ConstantTimeCompare(a, b); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

// ---------- Zeroize ----------

func TestZeroize(t *testing.T) {
	b := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: 0x%02x", i, v)
		}
	}
}

func TestZeroize_Empty(t *testing.T) {
	// Must not panic on empty/nil slices.
	Zeroize(nil)
	Zeroize([]byte{})
}

func TestZeroize_Large(t *testing.T) {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = 0xff
	}
	Zeroize(b)
	if !bytes.Equal(b, make([]byte, 4096)) {
		t.Fatal("large slice was not fully zeroed")
	}
}

// ---------- XORBytes ----------

func TestXORBytes_Basic(t *testing.T) {
	a := []byte{0xff, 0x00, 0xaa, 0x55}
	b := []byte{0x0f, 0xf0, 0x55, 0xaa}
	dst := make([]byte, 4)
	n := XORBytes(dst, a, b)
	if n != 4 {
		t.Fatalf("expected n=4, got %d", n)
	}
	want := []byte{0xf0, 0xf0, 0xff, 0xff}
	if !bytes.Equal(dst, want) {
		t.Fatalf("XOR mismatch: got %x, want %x", dst, want)
	}
}

func TestXORBytes_DifferentLengths(t *testing.T) {
	a := []byte{0xff, 0xff, 0xff}
	b := []byte{0x01, 0x02}
	dst := make([]byte, 10)
	n := XORBytes(dst, a, b)
	if n != 2 {
		t.Fatalf("expected n=2, got %d", n)
	}
	if dst[0] != 0xfe || dst[1] != 0xfd {
		t.Fatalf("unexpected result: %x", dst[:2])
	}
}

func TestXORBytes_Empty(t *testing.T) {
	n := XORBytes(nil, nil, nil)
	if n != 0 {
		t.Fatalf("expected n=0 for nil slices, got %d", n)
	}
}

func TestXORBytes_SelfXOR(t *testing.T) {
	a := []byte{0x12, 0x34, 0x56, 0x78}
	dst := make([]byte, 4)
	XORBytes(dst, a, a)
	for i, v := range dst {
		if v != 0 {
			t.Fatalf("self-XOR byte %d: expected 0, got 0x%02x", i, v)
		}
	}
}
