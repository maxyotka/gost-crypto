// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mgm

import (
	"crypto/cipher"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341215"
)

// fakeBlock is a cipher.Block with configurable block size, used to
// exercise the NewMGM bad-size error branch.
type fakeBlock struct{ bs int }

func (f *fakeBlock) BlockSize() int          { return f.bs }
func (f *fakeBlock) Encrypt(dst, src []byte) { copy(dst, src) }
func (f *fakeBlock) Decrypt(dst, src []byte) { copy(dst, src) }

var _ cipher.Block = (*fakeBlock)(nil)

func TestNewMGM_Errors(t *testing.T) {
	// Bad block size.
	if _, err := NewMGM(&fakeBlock{bs: 12}, 12); err == nil {
		t.Error("expected error for block size 12")
	}
	// Valid block cipher but bad tag size.
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	if _, err := NewMGM(b, 3); err == nil {
		t.Error("expected error for tag size 3")
	}
	if _, err := NewMGM(b, 17); err == nil {
		t.Error("expected error for tag size 17")
	}
}

func newKuzMGM(t *testing.T) cipher.AEAD {
	t.Helper()
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	a, err := NewMGM(b, 16)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSeal_BadNonceLen(t *testing.T) {
	a := newKuzMGM(t)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on wrong nonce length")
		}
	}()
	a.Seal(nil, make([]byte, 5), []byte("hi"), nil)
}

func TestSeal_NonceMSBNonZero(t *testing.T) {
	a := newKuzMGM(t)
	nonce := make([]byte, 16)
	nonce[0] = 0x80
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nonce MSB set")
		}
	}()
	a.Seal(nil, nonce, []byte("hi"), nil)
}

func TestOpen_Errors(t *testing.T) {
	a := newKuzMGM(t)
	nonce := make([]byte, 16)

	if _, err := a.Open(nil, make([]byte, 5), make([]byte, 16), nil); err == nil {
		t.Error("expected bad nonce length error")
	}
	badNonce := make([]byte, 16)
	badNonce[0] = 0x80
	if _, err := a.Open(nil, badNonce, make([]byte, 16), nil); err == nil {
		t.Error("expected nonce MSB error")
	}
	if _, err := a.Open(nil, nonce, make([]byte, 4), nil); err == nil {
		t.Error("expected ciphertext too short error")
	}
	// Valid Seal then tamper with tag to get auth failure.
	ct := a.Seal(nil, nonce, []byte("plaintext block!"), []byte("ad"))
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := a.Open(nil, nonce, tampered, []byte("ad")); err == nil {
		t.Error("expected authentication failure")
	}
}

// TestSealOpen_RoundTrip_PartialBlocks exercises the partial-last-block
// branches in deriveAndProcess for both AD and plaintext.
func TestSealOpen_RoundTrip_PartialBlocks(t *testing.T) {
	a := newKuzMGM(t)
	nonce := make([]byte, 16)
	// ad length 17, pt length 33 -> partial last block for both.
	ad := make([]byte, 17)
	pt := make([]byte, 33)
	for i := range ad {
		ad[i] = byte(i + 1)
	}
	for i := range pt {
		pt[i] = byte(i + 2)
	}
	ct := a.Seal(nil, nonce, pt, ad)
	out, err := a.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(pt) {
		t.Errorf("length mismatch: got %d want %d", len(out), len(pt))
	}
	for i := range pt {
		if out[i] != pt[i] {
			t.Errorf("mismatch at %d", i)
			break
		}
	}
}

// TestMagmaMGM covers the 8-byte block size branches (gf64, putUint32BE).
func TestMagmaMGM(t *testing.T) {
	b, _ := gost341215.NewMagma(make([]byte, 32))
	a, err := NewMGM(b, 8)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 8)
	pt := []byte("partial!")
	ad := []byte("ad-block-data-pad")
	ct := a.Seal(nil, nonce, pt, ad)
	out, err := a.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(pt) {
		t.Error("magma mgm roundtrip mismatch")
	}
}
