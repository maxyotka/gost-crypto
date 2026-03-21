// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341215"
)

// newKuznechik creates a Kuznechik cipher with a random 32-byte key.
func newKuznechik(t *testing.T) cipher.Block {
	t.Helper()
	key := make([]byte, gost341215.KuznechikKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := gost341215.NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newMagma creates a Magma cipher with a random 32-byte key.
func newMagma(t *testing.T) cipher.Block {
	t.Helper()
	key := make([]byte, gost341215.MagmaKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := gost341215.NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

// --- ECB ---

func testECBRoundtrip(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	plaintext := randBytes(t, 3*bs)

	ciphertext := make([]byte, len(plaintext))
	NewECBEncrypter(b).CryptBlocks(ciphertext, plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, len(ciphertext))
	NewECBDecrypter(b).CryptBlocks(recovered, ciphertext)

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("ECB roundtrip failed:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

func TestECBRoundtrip(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testECBRoundtrip(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testECBRoundtrip(t, newMagma(t)) })
}

// --- CBC ---

func testCBCRoundtrip(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	iv := randBytes(t, bs)
	plaintext := randBytes(t, 4*bs)

	ciphertext := make([]byte, len(plaintext))
	NewCBCEncrypter(b, iv).CryptBlocks(ciphertext, plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, len(ciphertext))
	NewCBCDecrypter(b, iv).CryptBlocks(recovered, ciphertext)

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("CBC roundtrip failed:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

func TestCBCRoundtrip(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testCBCRoundtrip(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testCBCRoundtrip(t, newMagma(t)) })
}

func testCBCChunked(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	iv := randBytes(t, bs)
	plaintext := randBytes(t, 6*bs)

	// Encrypt in one call.
	ctFull := make([]byte, len(plaintext))
	NewCBCEncrypter(b, iv).CryptBlocks(ctFull, plaintext)

	// Encrypt in two calls (3 blocks each).
	ctChunked := make([]byte, len(plaintext))
	enc := NewCBCEncrypter(b, iv)
	enc.CryptBlocks(ctChunked[:3*bs], plaintext[:3*bs])
	enc.CryptBlocks(ctChunked[3*bs:], plaintext[3*bs:])

	if !bytes.Equal(ctFull, ctChunked) {
		t.Fatal("CBC chunked encrypt differs from single-call encrypt")
	}

	// Decrypt in two calls.
	ptChunked := make([]byte, len(ctFull))
	dec := NewCBCDecrypter(b, iv)
	dec.CryptBlocks(ptChunked[:3*bs], ctFull[:3*bs])
	dec.CryptBlocks(ptChunked[3*bs:], ctFull[3*bs:])

	if !bytes.Equal(plaintext, ptChunked) {
		t.Fatal("CBC chunked decrypt differs from original plaintext")
	}
}

func TestCBCChunked(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testCBCChunked(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testCBCChunked(t, newMagma(t)) })
}

// --- CTR ---

func testCTRRoundtrip(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	iv := randBytes(t, bs)

	// Non-block-aligned plaintext to test streaming.
	plaintext := randBytes(t, 5*bs+7)

	ciphertext := make([]byte, len(plaintext))
	NewCTR(b, iv).XORKeyStream(ciphertext, plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, len(ciphertext))
	NewCTR(b, iv).XORKeyStream(recovered, ciphertext)

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("CTR roundtrip failed:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

func TestCTRRoundtrip(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testCTRRoundtrip(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testCTRRoundtrip(t, newMagma(t)) })
}

// --- OFB ---

func testOFBRoundtrip(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	iv := randBytes(t, bs)

	// Non-block-aligned plaintext.
	plaintext := randBytes(t, 3*bs+11)

	ciphertext := make([]byte, len(plaintext))
	NewOFB(b, iv).XORKeyStream(ciphertext, plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, len(ciphertext))
	NewOFB(b, iv).XORKeyStream(recovered, ciphertext)

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("OFB roundtrip failed:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

func TestOFBRoundtrip(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testOFBRoundtrip(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testOFBRoundtrip(t, newMagma(t)) })
}

// --- CFB ---

func testCFBRoundtrip(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()
	iv := randBytes(t, bs)

	// Non-block-aligned plaintext.
	plaintext := randBytes(t, 4*bs+3)

	ciphertext := make([]byte, len(plaintext))
	NewCFBEncrypter(b, iv).XORKeyStream(ciphertext, plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext equals plaintext")
	}

	recovered := make([]byte, len(ciphertext))
	NewCFBDecrypter(b, iv).XORKeyStream(recovered, ciphertext)

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("CFB roundtrip failed:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

func TestCFBRoundtrip(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testCFBRoundtrip(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testCFBRoundtrip(t, newMagma(t)) })
}

// --- MAC ---

func testMACConsistency(t *testing.T, b cipher.Block) {
	t.Helper()
	bs := b.BlockSize()

	data := randBytes(t, 5*bs+13)

	mac1, err := NewMAC(b, bs)
	if err != nil {
		t.Fatal(err)
	}
	mac1.Write(data)
	tag1 := mac1.Sum(nil)

	// Same input must produce the same tag.
	mac2, _ := NewMAC(b, bs)
	mac2.Write(data)
	tag2 := mac2.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatalf("MAC tags differ for same input:\n  tag1: %x\n  tag2: %x", tag1, tag2)
	}

	// Different input must produce a different tag.
	differentData := make([]byte, len(data))
	copy(differentData, data)
	differentData[0] ^= 0xFF

	mac3, _ := NewMAC(b, bs)
	mac3.Write(differentData)
	tag3 := mac3.Sum(nil)

	if bytes.Equal(tag1, tag3) {
		t.Fatal("MAC tags are equal for different inputs")
	}
}

func TestMACConsistency(t *testing.T) {
	t.Run("Kuznechik", func(t *testing.T) { testMACConsistency(t, newKuznechik(t)) })
	t.Run("Magma", func(t *testing.T) { testMACConsistency(t, newMagma(t)) })
}

func TestMACReset(t *testing.T) {
	b := newKuznechik(t)
	bs := b.BlockSize()

	mac1, err := NewMAC(b, bs)
	if err != nil {
		t.Fatal(err)
	}

	data := randBytes(t, 2*bs+5)

	mac1.Write(data)
	tag1 := mac1.Sum(nil)

	// Reset and re-compute.
	mac1.Reset()
	mac1.Write(data)
	tag2 := mac1.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatalf("MAC after Reset differs:\n  tag1: %x\n  tag2: %x", tag1, tag2)
	}
}

func TestMACPartialWrites(t *testing.T) {
	b := newKuznechik(t)
	bs := b.BlockSize()

	data := randBytes(t, 4*bs+9)

	// Single write.
	mac1, _ := NewMAC(b, bs)
	mac1.Write(data)
	tag1 := mac1.Sum(nil)

	// Multiple partial writes.
	mac2, _ := NewMAC(b, bs)
	mac2.Write(data[:7])
	mac2.Write(data[7:bs])
	mac2.Write(data[bs : 2*bs+3])
	mac2.Write(data[2*bs+3:])
	tag2 := mac2.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatalf("MAC partial writes differ:\n  tag1: %x\n  tag2: %x", tag1, tag2)
	}
}

func TestMACInvalidSize(t *testing.T) {
	b := newKuznechik(t)
	bs := b.BlockSize()

	if _, err := NewMAC(b, 0); err == nil {
		t.Fatal("expected error for macSize=0")
	}
	if _, err := NewMAC(b, bs+1); err == nil {
		t.Fatal("expected error for macSize > blockSize")
	}
}

func TestMACTruncation(t *testing.T) {
	b := newKuznechik(t)

	data := []byte("test data for truncated mac")

	mac1, _ := NewMAC(b, 8)
	mac1.Write(data)
	tag := mac1.Sum(nil)

	if len(tag) != 8 {
		t.Fatalf("expected tag length 8, got %d", len(tag))
	}
}
