// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341215"
)

// fakeBlock is a cipher.Block with a configurable block size used to
// exercise the unsupported-block-size panic in deriveSubkeys.
type fakeBlock struct{ bs int }

func (f *fakeBlock) BlockSize() int          { return f.bs }
func (f *fakeBlock) Encrypt(dst, src []byte) { copy(dst, src) }
func (f *fakeBlock) Decrypt(dst, src []byte) { copy(dst, src) }

var _ cipher.Block = (*fakeBlock)(nil)

func TestCMAC_Magma(t *testing.T) {
	// Exercise the case 8 branch in deriveSubkeys.
	b, _ := gost341215.NewMagma(make([]byte, 32))
	mac := NewCMAC(b)
	mac.Write([]byte("hello"))
	_ = mac.Sum(nil)
}

func TestCMAC_UnsupportedBlockSize_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unsupported block size")
		}
	}()
	NewCMAC(&fakeBlock{bs: 12})
}

func TestCMAC_ResetSizeBlockSize(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	mac := NewCMAC(b)
	mac.Write([]byte("hello world"))
	if mac.Size() != 16 {
		t.Errorf("Size() = %d; want 16", mac.Size())
	}
	if mac.BlockSize() != 16 {
		t.Errorf("BlockSize() = %d; want 16", mac.BlockSize())
	}
	sum1 := mac.Sum(nil)
	mac.Reset()
	mac.Write([]byte("hello world"))
	sum2 := mac.Sum(nil)
	if !bytes.Equal(sum1, sum2) {
		t.Error("Reset+Write produced different result")
	}
}

// TestCMAC_WriteBufferFlow exercises the bufferred Write path where we
// already have a partial buffer and the new Write fills and exceeds it.
func TestCMAC_WriteBufferFlow(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))

	// Build reference: one-shot write of 50 bytes.
	refData := make([]byte, 50)
	for i := range refData {
		refData[i] = byte(i)
	}
	ref := NewCMAC(b)
	ref.Write(refData)
	refSum := ref.Sum(nil)

	// Incremental: write 5 bytes first (fills partial buf), then 45 bytes
	// (fills remaining buf space, flushes, and processes more full blocks).
	inc := NewCMAC(b)
	inc.Write(refData[:5])
	inc.Write(refData[5:])
	if !bytes.Equal(inc.Sum(nil), refSum) {
		t.Error("incremental write mismatch")
	}

	// Write that exactly fills the current buffer and nothing more.
	inc2 := NewCMAC(b)
	inc2.Write(refData[:5])
	inc2.Write(refData[5:16]) // fills to full block boundary (buf full)
	inc2.Write(refData[16:])
	if !bytes.Equal(inc2.Sum(nil), refSum) {
		t.Error("incremental boundary write mismatch")
	}

	// Single write smaller than block size (hits the final "if len(p)>0" buffering).
	small := NewCMAC(b)
	small.Write(refData[:7])
	_ = small.Sum(nil)
}

func TestUnwrapKey_BadMAC(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}
	wrapped, err := WrapKey(b, cek)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with MAC
	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[0] ^= 0xFF
	if _, err := UnwrapKey(b, tampered); err == nil {
		t.Error("expected MAC verification failure")
	}
}

func TestUnwrapKey_TooShort(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	if _, err := UnwrapKey(b, make([]byte, 5)); err == nil {
		t.Error("expected too-short error")
	}
}

func TestUnwrapKey_InvalidLength(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	// 4 + 20 — 20 is not multiple of 16.
	if _, err := UnwrapKey(b, make([]byte, 24)); err == nil {
		t.Error("expected invalid-length error")
	}
}

func TestWrapKey_BadCEK(t *testing.T) {
	b, _ := gost341215.NewKuznechik(make([]byte, 32))
	if _, err := WrapKey(b, nil); err == nil {
		t.Error("expected error for empty CEK")
	}
	if _, err := WrapKey(b, make([]byte, 7)); err == nil {
		t.Error("expected error for non-block-multiple CEK")
	}
}
