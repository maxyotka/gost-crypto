// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mgm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341215"
)

// TestMGMKuznechikRFC9058 tests against the test vector from RFC 9058 Appendix A.
func TestMGMKuznechikRFC9058(t *testing.T) {
	key, _ := hex.DecodeString("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
	nonce, _ := hex.DecodeString("1122334455667700FFEEDDCCBBAA9988")
	aad, _ := hex.DecodeString("0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505")
	plaintext, _ := hex.DecodeString("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011AABBCC")
	wantCiphertext, _ := hex.DecodeString("A9757B8147956E9055B8A33DE89F42FC8075D2212BF9FD5BD3F7069AADC16B39497AB15915A6BA85936B5D0EA9F6851CC60C14D4D3F883D0AB94420695C76DEB2C7552")
	wantTag, _ := hex.DecodeString("CF5D656F40C34F5C46E8BB0E29FCDB4C")

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	// Test Seal.
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	gotCT := sealed[:len(plaintext)]
	gotTag := sealed[len(plaintext):]

	if !bytes.Equal(gotCT, wantCiphertext) {
		t.Fatalf("Seal ciphertext mismatch:\n got  %X\n want %X", gotCT, wantCiphertext)
	}
	if !bytes.Equal(gotTag, wantTag) {
		t.Fatalf("Seal tag mismatch:\n got  %X\n want %X", gotTag, wantTag)
	}

	// Test Open.
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open plaintext mismatch:\n got  %X\n want %X", opened, plaintext)
	}
}

// TestMGMSealOpenRoundtrip tests that Seal followed by Open returns the original plaintext.
func TestMGMSealOpenRoundtrip(t *testing.T) {
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] &= 0x7F // MSB must be 0

	plaintext := make([]byte, 123)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	aad := make([]byte, 45)
	if _, err := rand.Read(aad); err != nil {
		t.Fatal(err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("roundtrip plaintext mismatch")
	}
}

// TestMGMOpenTamperedCiphertext verifies that Open fails when ciphertext is modified.
func TestMGMOpenTamperedCiphertext(t *testing.T) {
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] &= 0x7F

	plaintext := []byte("test plaintext for tampering")
	aad := []byte("additional data")

	sealed := aead.Seal(nil, nonce, plaintext, aad)

	// Tamper with the ciphertext portion.
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0xFF

	_, err = aead.Open(nil, nonce, tampered, aad)
	if err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext")
	}
}

// TestMGMOpenWrongAAD verifies that Open fails when AAD differs.
func TestMGMOpenWrongAAD(t *testing.T) {
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] &= 0x7F

	plaintext := []byte("test plaintext")
	aad := []byte("correct additional data")

	sealed := aead.Seal(nil, nonce, plaintext, aad)

	wrongAAD := []byte("wrong additional data")
	_, err = aead.Open(nil, nonce, sealed, wrongAAD)
	if err == nil {
		t.Fatal("expected Open to fail with wrong AAD")
	}
}

// TestMGMEmptyPlaintext tests authentication with empty plaintext and non-empty AAD.
func TestMGMEmptyPlaintext(t *testing.T) {
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] &= 0x7F

	aad := []byte("only additional data, no plaintext")

	sealed := aead.Seal(nil, nonce, nil, aad)
	if len(sealed) != aead.Overhead() {
		t.Fatalf("expected sealed length %d, got %d", aead.Overhead(), len(sealed))
	}

	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if len(opened) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(opened))
	}
}

// TestMGMPlaintextWithoutAAD tests encryption without additional data.
func TestMGMPlaintextWithoutAAD(t *testing.T) {
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewMGM(block, 16)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	nonce[0] &= 0x7F

	plaintext := []byte("plaintext without additional data")

	sealed := aead.Seal(nil, nonce, plaintext, nil)

	opened, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("roundtrip plaintext mismatch")
	}
}
