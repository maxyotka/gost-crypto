// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341112"
	"github.com/maxyotka/gost-crypto/gost341215"
)

// TestHMAC256Deterministic verifies that HMAC-Stribog-256 produces a
// deterministic 32-byte tag.
func TestHMAC256Deterministic(t *testing.T) {
	key := []byte("test-hmac-key-for-stribog-256!!")
	msg := []byte("hello, GOST HMAC")

	h1 := NewHMAC256(key)
	h1.Write(msg)
	tag1 := h1.Sum(nil)

	if len(tag1) != 32 {
		t.Fatalf("HMAC-256 tag length = %d, want 32", len(tag1))
	}

	h2 := NewHMAC256(key)
	h2.Write(msg)
	tag2 := h2.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatal("HMAC-256 is not deterministic")
	}

	t.Logf("HMAC-256 tag: %x", tag1)
}

// TestHMAC512Deterministic verifies that HMAC-Stribog-512 produces a
// deterministic 64-byte tag.
func TestHMAC512Deterministic(t *testing.T) {
	key := []byte("test-hmac-key-for-stribog-512!!")
	msg := []byte("hello, GOST HMAC-512")

	h1 := NewHMAC512(key)
	h1.Write(msg)
	tag1 := h1.Sum(nil)

	if len(tag1) != 64 {
		t.Fatalf("HMAC-512 tag length = %d, want 64", len(tag1))
	}

	h2 := NewHMAC512(key)
	h2.Write(msg)
	tag2 := h2.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatal("HMAC-512 is not deterministic")
	}

	t.Logf("HMAC-512 tag: %x", tag1)
}

// TestKDF256Basic verifies that KDF256 returns 32 bytes and is deterministic.
func TestKDF256Basic(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	label := []byte("label")
	seed := []byte("seed-value")

	dk1 := KDF256(key, label, seed)
	if len(dk1) != 32 {
		t.Fatalf("KDF256 output length = %d, want 32", len(dk1))
	}

	dk2 := KDF256(key, label, seed)
	if !bytes.Equal(dk1, dk2) {
		t.Fatal("KDF256 is not deterministic")
	}

	// Different label must produce different key.
	dk3 := KDF256(key, []byte("other"), seed)
	if bytes.Equal(dk1, dk3) {
		t.Fatal("KDF256 produced same output for different labels")
	}

	t.Logf("KDF256 derived key: %x", dk1)
}

// TestPBKDF2Vector verifies the PBKDF2 production test vector from SPEC.md.
//
//	PBKDF2("password", "saltsaltsaltsal!", iter=1, keyLen=32, PRF=HMAC-Stribog-256) =
//	  0c94170021f7f800c7330be0ffd21b350cc278559533d9c8a04827a87646f12a
func TestPBKDF2Vector(t *testing.T) {
	password := []byte("password")
	salt := []byte("saltsaltsaltsal!")
	iter := 1
	keyLen := 32

	dk := PBKDF2(password, salt, iter, keyLen, gost341112.New256)

	expected, _ := hex.DecodeString("0c94170021f7f800c7330be0ffd21b350cc278559533d9c8a04827a87646f12a")
	if !bytes.Equal(dk, expected) {
		t.Fatalf("PBKDF2 mismatch:\n  got  %x\n  want %x", dk, expected)
	}
}

// TestPBKDF2Deterministic verifies PBKDF2 is deterministic across calls.
func TestPBKDF2Deterministic(t *testing.T) {
	password := []byte("my-secret-password")
	salt := []byte("random-salt-1234")
	iter := 10
	keyLen := 64

	dk1 := PBKDF2(password, salt, iter, keyLen, gost341112.New512)
	dk2 := PBKDF2(password, salt, iter, keyLen, gost341112.New512)

	if !bytes.Equal(dk1, dk2) {
		t.Fatal("PBKDF2 is not deterministic")
	}

	if len(dk1) != keyLen {
		t.Fatalf("PBKDF2 output length = %d, want %d", len(dk1), keyLen)
	}
}

// TestCMACRoundtrip verifies CMAC consistency: computing the MAC twice over
// the same data yields the same tag.
func TestCMACRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("CMAC test data for GOST Kuznechik cipher")

	mac1 := NewCMAC(block)
	mac1.Write(data)
	tag1 := mac1.Sum(nil)

	if len(tag1) != 16 {
		t.Fatalf("CMAC tag length = %d, want 16", len(tag1))
	}

	mac2 := NewCMAC(block)
	mac2.Write(data)
	tag2 := mac2.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatal("CMAC is not deterministic")
	}

	// Verify incremental vs one-shot.
	mac3 := NewCMAC(block)
	mac3.Write(data[:10])
	mac3.Write(data[10:])
	tag3 := mac3.Sum(nil)

	if !bytes.Equal(tag1, tag3) {
		t.Fatal("CMAC incremental != one-shot")
	}

	t.Logf("CMAC tag: %x", tag1)
}

// TestCMACEmpty verifies CMAC on an empty message.
func TestCMACEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	mac := NewCMAC(block)
	tag := mac.Sum(nil)

	if len(tag) != 16 {
		t.Fatalf("CMAC empty tag length = %d, want 16", len(tag))
	}
	t.Logf("CMAC empty tag: %x", tag)
}

// TestKeyWrapUnwrap verifies that WrapKey followed by UnwrapKey returns
// the original CEK.
func TestKeyWrapUnwrap(t *testing.T) {
	kekBytes := bytes.Repeat([]byte{0xAA}, 32)
	kek, err := gost341215.NewKuznechik(kekBytes)
	if err != nil {
		t.Fatal(err)
	}

	// CEK must be a multiple of block size (16 bytes).
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}

	wrapped, err := WrapKey(kek, cek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	// Wrapped = 4-byte MAC + encrypted CEK.
	if len(wrapped) != 4+len(cek) {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), 4+len(cek))
	}

	unwrapped, err := UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if !bytes.Equal(cek, unwrapped) {
		t.Fatalf("unwrapped key mismatch:\n  got  %x\n  want %x", unwrapped, cek)
	}
}

// TestKeyWrapTampered verifies that tampering with the wrapped key causes
// UnwrapKey to fail.
func TestKeyWrapTampered(t *testing.T) {
	kekBytes := bytes.Repeat([]byte{0xBB}, 32)
	kek, err := gost341215.NewKuznechik(kekBytes)
	if err != nil {
		t.Fatal(err)
	}

	cek := bytes.Repeat([]byte{0xCC}, 16)
	wrapped, err := WrapKey(kek, cek)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the MAC.
	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[0] ^= 0xFF

	_, err = UnwrapKey(kek, tampered)
	if err == nil {
		t.Fatal("UnwrapKey should fail on tampered data")
	}
}

// TestKeyWrapInvalidLength verifies WrapKey rejects invalid CEK lengths.
func TestKeyWrapInvalidLength(t *testing.T) {
	kekBytes := bytes.Repeat([]byte{0xDD}, 32)
	kek, err := gost341215.NewKuznechik(kekBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = WrapKey(kek, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("WrapKey should reject CEK that is not a multiple of block size")
	}

	_, err = WrapKey(kek, nil)
	if err == nil {
		t.Fatal("WrapKey should reject empty CEK")
	}
}
