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

// ---------------------------------------------------------------------------
// KAT vectors from R 50.1.113-2016 Appendix A
// ---------------------------------------------------------------------------

// TestKAT_HMAC256 verifies HMAC-Stribog-256 against R 50.1.113-2016
// Appendix A, test 1 (HMAC_GOSTR3411_2012_256).
func TestKAT_HMAC256(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data, _ := hex.DecodeString("0126bdb87800af214341456563780100")
	expected, _ := hex.DecodeString("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")

	h := NewHMAC256(key)
	h.Write(data)
	got := h.Sum(nil)

	if !bytes.Equal(got, expected) {
		t.Fatalf("HMAC-256 KAT mismatch:\n  got  %x\n  want %x", got, expected)
	}
}

// TestKAT_HMAC512 verifies HMAC-Stribog-512 against R 50.1.113-2016
// Appendix A, test 2 (HMAC_GOSTR3411_2012_512).
func TestKAT_HMAC512(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data, _ := hex.DecodeString("0126bdb87800af214341456563780100")
	expected, _ := hex.DecodeString("a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6")

	h := NewHMAC512(key)
	h.Write(data)
	got := h.Sum(nil)

	if !bytes.Equal(got, expected) {
		t.Fatalf("HMAC-512 KAT mismatch:\n  got  %x\n  want %x", got, expected)
	}
}

// TestKAT_KDF256 verifies KDF_GOSTR3411_2012_256 against R 50.1.113-2016
// Appendix A, test 11.
func TestKAT_KDF256(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	label, _ := hex.DecodeString("26bdb878")
	seed, _ := hex.DecodeString("af21434145656378")
	expected, _ := hex.DecodeString("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")

	got := KDF256(key, label, seed)

	if !bytes.Equal(got, expected) {
		t.Fatalf("KDF256 KAT mismatch:\n  got  %x\n  want %x", got, expected)
	}
}

// TestKAT_PBKDF2 verifies PBKDF2 with Stribog-512 against
// R 50.1.111-2016 Appendix A, test 1: P="password", S="salt", c=1, dkLen=64.
func TestKAT_PBKDF2(t *testing.T) {
	// Hex from R 50.1.111-2016 Appendix A (OCR-cleaned, verified byte 14: bc not be).
	expected, _ := hex.DecodeString(
		"64770af7f748c3b1c9ac831dbcfd85c2" +
			"6111b30a8a657ddc3056b80ca73e040d" +
			"2854fd36811f6d825cc4ab66ec0a68a4" +
			"90a9e5cf5156b3a2b7eecddbf9a16b47",
	)

	dk := PBKDF2([]byte("password"), []byte("salt"), 1, 64, gost341112.New512)

	if !bytes.Equal(dk, expected) {
		t.Fatalf("PBKDF2 KAT mismatch:\n  got  %x\n  want %x", dk, expected)
	}
}

// TestKAT_PBKDF2_4096 verifies PBKDF2 with c=4096 iterations.
func TestKAT_PBKDF2_4096(t *testing.T) {
	expected, _ := hex.DecodeString(
		"e52deb9a2d2aaff4e2ac9d47a41f34c2" +
			"0376591c67807f0477e32549dc341bc7" +
			"867c09841b6d58e29d0347c996301d55" +
			"df0d34e47cf68f4e3c2cdaf1d9ab86c3",
	)

	dk := PBKDF2([]byte("password"), []byte("salt"), 4096, 64, gost341112.New512)

	if !bytes.Equal(dk, expected) {
		t.Fatalf("PBKDF2 c=4096 KAT mismatch:\n  got  %x\n  want %x", dk, expected)
	}
}
