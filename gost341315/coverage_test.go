// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import (
	"crypto/cipher"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341215"
)

func newKuz(t *testing.T) cipher.Block {
	t.Helper()
	b, err := gost341215.NewKuznechik(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newMag(t *testing.T) cipher.Block {
	t.Helper()
	b, err := gost341215.NewMagma(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- BlockSize methods (trivial getters) ---

func TestBlockSizeMethods(t *testing.T) {
	b := newKuz(t)
	iv := make([]byte, 16)
	if m := NewCBCEncrypter(b, iv); m.BlockSize() != 16 {
		t.Error("cbcEncrypter BlockSize")
	}
	if m := NewCBCDecrypter(b, iv); m.BlockSize() != 16 {
		t.Error("cbcDecrypter BlockSize")
	}
	if m := NewECBEncrypter(b); m.BlockSize() != 16 {
		t.Error("ecbEncrypter BlockSize")
	}
	if m := NewECBDecrypter(b); m.BlockSize() != 16 {
		t.Error("ecbDecrypter BlockSize")
	}
	mac, err := NewMAC(b, 8)
	if err != nil {
		t.Fatal(err)
	}
	if mac.Size() != 8 {
		t.Error("mac Size")
	}
	if mac.BlockSize() != 16 {
		t.Error("mac BlockSize")
	}
}

// --- Panic paths ---

func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic", name)
		}
	}()
	fn()
}

func TestCBC_BadIV(t *testing.T) {
	b := newKuz(t)
	expectPanic(t, "cbc enc short iv", func() { NewCBCEncrypter(b, make([]byte, 5)) })
	expectPanic(t, "cbc enc bad iv mod", func() { NewCBCEncrypter(b, make([]byte, 17)) })
	expectPanic(t, "cbc dec short iv", func() { NewCBCDecrypter(b, make([]byte, 5)) })
	expectPanic(t, "cbc dec bad iv mod", func() { NewCBCDecrypter(b, make([]byte, 17)) })
}

func TestCFB_BadIV(t *testing.T) {
	b := newKuz(t)
	expectPanic(t, "cfb enc short iv", func() { NewCFBEncrypter(b, make([]byte, 5)) })
	expectPanic(t, "cfb enc bad iv mod", func() { NewCFBEncrypter(b, make([]byte, 17)) })
	expectPanic(t, "cfb dec short iv", func() { NewCFBDecrypter(b, make([]byte, 5)) })
	expectPanic(t, "cfb dec bad iv mod", func() { NewCFBDecrypter(b, make([]byte, 17)) })
}

func TestOFB_BadIV(t *testing.T) {
	b := newKuz(t)
	expectPanic(t, "ofb short iv", func() { NewOFB(b, make([]byte, 5)) })
	expectPanic(t, "ofb bad iv mod", func() { NewOFB(b, make([]byte, 17)) })
}

func TestCTR_BadIV(t *testing.T) {
	b := newKuz(t)
	expectPanic(t, "ctr bad iv", func() { NewCTR(b, make([]byte, 5)) })
}

func TestCBC_CryptBlocks_Panics(t *testing.T) {
	b := newKuz(t)
	iv := make([]byte, 16)
	enc := NewCBCEncrypter(b, iv)
	expectPanic(t, "cbc enc partial block", func() {
		enc.CryptBlocks(make([]byte, 16), make([]byte, 5))
	})
	enc2 := NewCBCEncrypter(b, iv)
	expectPanic(t, "cbc enc short dst", func() {
		enc2.CryptBlocks(make([]byte, 5), make([]byte, 16))
	})
	dec := NewCBCDecrypter(b, iv)
	expectPanic(t, "cbc dec partial block", func() {
		dec.CryptBlocks(make([]byte, 16), make([]byte, 5))
	})
	dec2 := NewCBCDecrypter(b, iv)
	expectPanic(t, "cbc dec short dst", func() {
		dec2.CryptBlocks(make([]byte, 5), make([]byte, 16))
	})
}

func TestECB_CryptBlocks_Panics(t *testing.T) {
	b := newKuz(t)
	enc := NewECBEncrypter(b)
	expectPanic(t, "ecb enc partial", func() {
		enc.CryptBlocks(make([]byte, 16), make([]byte, 5))
	})
	enc2 := NewECBEncrypter(b)
	expectPanic(t, "ecb enc short dst", func() {
		enc2.CryptBlocks(make([]byte, 5), make([]byte, 16))
	})
	dec := NewECBDecrypter(b)
	expectPanic(t, "ecb dec partial", func() {
		dec.CryptBlocks(make([]byte, 16), make([]byte, 5))
	})
	dec2 := NewECBDecrypter(b)
	expectPanic(t, "ecb dec short dst", func() {
		dec2.CryptBlocks(make([]byte, 5), make([]byte, 16))
	})
}

func TestStream_XOR_Panics(t *testing.T) {
	b := newKuz(t)
	iv := make([]byte, 16)
	expectPanic(t, "cfb enc short dst", func() {
		s := NewCFBEncrypter(b, iv)
		s.XORKeyStream(make([]byte, 1), make([]byte, 16))
	})
	expectPanic(t, "cfb dec short dst", func() {
		s := NewCFBDecrypter(b, iv)
		s.XORKeyStream(make([]byte, 1), make([]byte, 16))
	})
	expectPanic(t, "ofb short dst", func() {
		s := NewOFB(b, iv)
		s.XORKeyStream(make([]byte, 1), make([]byte, 16))
	})
	expectPanic(t, "ctr short dst", func() {
		s := NewCTR(b, iv)
		s.XORKeyStream(make([]byte, 1), make([]byte, 16))
	})
}

// --- m > n shift register cases ---

func TestCBC_MGreaterN(t *testing.T) {
	b := newKuz(t)
	// m = 2n, so iv is 32 bytes, register holds 2 blocks.
	iv := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i)
	}
	pt := make([]byte, 48) // 3 blocks
	enc := NewCBCEncrypter(b, iv)
	ct := make([]byte, len(pt))
	enc.CryptBlocks(ct, pt)
	dec := NewCBCDecrypter(b, iv)
	out := make([]byte, len(pt))
	dec.CryptBlocks(out, ct)
	for i := range pt {
		if out[i] != pt[i] {
			t.Fatalf("cbc m>n roundtrip mismatch at %d", i)
		}
	}
}

func TestCFB_MGreaterN(t *testing.T) {
	b := newKuz(t)
	iv := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i)
	}
	pt := []byte("hello, this is a longer plaintext example for cfb")
	ct := make([]byte, len(pt))
	NewCFBEncrypter(b, iv).XORKeyStream(ct, pt)
	out := make([]byte, len(pt))
	NewCFBDecrypter(b, iv).XORKeyStream(out, ct)
	for i := range pt {
		if out[i] != pt[i] {
			t.Fatalf("cfb m>n roundtrip mismatch")
		}
	}
}

func TestOFB_MGreaterN(t *testing.T) {
	b := newKuz(t)
	iv := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i)
	}
	pt := []byte("hello, this is a longer plaintext example for ofb")
	ct := make([]byte, len(pt))
	NewOFB(b, iv).XORKeyStream(ct, pt)
	out := make([]byte, len(pt))
	NewOFB(b, iv).XORKeyStream(out, ct)
	for i := range pt {
		if out[i] != pt[i] {
			t.Fatalf("ofb m>n roundtrip mismatch")
		}
	}
}

// --- MAC bad size + panic for unsupported block size ---

// fakeBlock is a cipher.Block with a configurable block size for
// exercising panic branches.
type fakeBlock struct{ bs int }

func (f *fakeBlock) BlockSize() int          { return f.bs }
func (f *fakeBlock) Encrypt(dst, src []byte) { copy(dst, src) }
func (f *fakeBlock) Decrypt(dst, src []byte) { copy(dst, src) }

func TestMAC_UnsupportedBlockSize_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unsupported block size")
		}
	}()
	_, _ = NewMAC(&fakeBlock{bs: 12}, 4)
}

func TestMAC_BadSize(t *testing.T) {
	b := newKuz(t)
	if _, err := NewMAC(b, 0); err == nil {
		t.Error("expected error for size 0")
	}
	if _, err := NewMAC(b, 100); err == nil {
		t.Error("expected error for size > blockSize")
	}
}

func TestMAC_MagmaWorks(t *testing.T) {
	// Magma has 8-byte blocks — exercises the case 8 branch in deriveSubkeys.
	b := newMag(t)
	mac, err := NewMAC(b, 4)
	if err != nil {
		t.Fatal(err)
	}
	mac.Write([]byte("hello"))
	_ = mac.Sum(nil)
	mac.Reset()
}

// --- xorBytes edge cases ---

func TestXorBytes_Mismatched(t *testing.T) {
	dst := make([]byte, 10)
	a := make([]byte, 5)
	b := make([]byte, 10)
	for i := range a {
		a[i] = byte(i + 1)
	}
	for i := range b {
		b[i] = byte(i + 2)
	}
	xorBytes(dst, a, b)
	// Second arm: len(b) < n
	xorBytes(dst, b, a)
	// Only first 5 bytes processed
	for i := 0; i < 5; i++ {
		if dst[i] != (a[i] ^ b[i]) {
			t.Errorf("xorBytes mismatched second arm at %d", i)
		}
	}
}
