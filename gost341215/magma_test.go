// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vector from ГОСТ Р 34.12-2015, Section 5.1 (Magma).
func TestMagmaEncryptDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt, _ := hex.DecodeString("fedcba9876543210")
	want, _ := hex.DecodeString("4ee901e5c2d8ca3d")

	c, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, MagmaBlockSize)
	c.Encrypt(ct, pt)

	if !bytes.Equal(ct, want) {
		t.Fatalf("Encrypt:\n got  %x\n want %x", ct, want)
	}

	// Roundtrip: decrypt should recover plaintext.
	got := make([]byte, MagmaBlockSize)
	c.Decrypt(got, ct)

	if !bytes.Equal(got, pt) {
		t.Fatalf("Decrypt:\n got  %x\n want %x", got, pt)
	}
}

func TestMagmaRoundtrip(t *testing.T) {
	// Use an arbitrary key and plaintext to verify roundtrip.
	key := make([]byte, MagmaKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	pt := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	c, err := NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, MagmaBlockSize)
	c.Encrypt(ct, pt)

	got := make([]byte, MagmaBlockSize)
	c.Decrypt(got, ct)

	if !bytes.Equal(got, pt) {
		t.Fatalf("Roundtrip failed:\n got  %x\n want %x", got, pt)
	}
}

func TestMagmaInvalidKeySize(t *testing.T) {
	_, err := NewMagma(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}
