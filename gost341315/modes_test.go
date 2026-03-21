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
	"encoding/hex"
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

// ============================================================================
// KAT (Known Answer Tests) from GOST R 34.13-2015, Appendix A
// ============================================================================

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex literal: " + s)
	}
	return b
}

// --- A.1 Kuznechik (n=128) ---

var (
	kuznechikKATKey = mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	kuznechikKATPT = [][]byte{
		mustHex("1122334455667700ffeeddccbbaa9988"),
		mustHex("00112233445566778899aabbcceeff0a"),
		mustHex("112233445566778899aabbcceeff0a00"),
		mustHex("2233445566778899aabbcceeff0a0011"),
	}
)

// --- A.2 Magma (n=64) ---

var (
	magmaKATKey = mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	magmaKATPT = [][]byte{
		mustHex("92def06b3c130a59"),
		mustHex("db54c704f8189d20"),
		mustHex("4a98fb2e67a8024c"),
		mustHex("8912409b17b57e41"),
	}
)

// TestKAT_ECB_Kuznechik verifies ECB encryption/decryption against
// GOST R 34.13-2015, A.1.1.
func TestKAT_ECB_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	expectedCT := [][]byte{
		mustHex("7f679d90bebc24305a468d42b9d4edcd"),
		mustHex("b429912c6e0032f9285452d76718d08b"),
		mustHex("f0ca33549d247ceef3f5a5313bd4b157"),
		mustHex("d0b09ccde830b9eb3a02c4c5aa8ada98"),
	}

	enc := NewECBEncrypter(b)
	dec := NewECBDecrypter(b)

	for i, pt := range kuznechikKATPT {
		ct := make([]byte, len(pt))
		enc.CryptBlocks(ct, pt)
		if !bytes.Equal(ct, expectedCT[i]) {
			t.Fatalf("block %d encrypt:\n  want: %x\n  got:  %x", i+1, expectedCT[i], ct)
		}

		recovered := make([]byte, len(ct))
		dec.CryptBlocks(recovered, ct)
		if !bytes.Equal(recovered, pt) {
			t.Fatalf("block %d decrypt:\n  want: %x\n  got:  %x", i+1, pt, recovered)
		}
	}
}

// TestKAT_ECB_Magma verifies ECB encryption/decryption against
// GOST R 34.13-2015, A.2.1.
func TestKAT_ECB_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	expectedCT := [][]byte{
		mustHex("2b073f0494f372a0"),
		mustHex("de70e715d3556e48"),
		mustHex("11d8d9e9eacfbc1e"),
		mustHex("7c68260996c67efb"),
	}

	enc := NewECBEncrypter(b)
	dec := NewECBDecrypter(b)

	for i, pt := range magmaKATPT {
		ct := make([]byte, len(pt))
		enc.CryptBlocks(ct, pt)
		if !bytes.Equal(ct, expectedCT[i]) {
			t.Fatalf("block %d encrypt:\n  want: %x\n  got:  %x", i+1, expectedCT[i], ct)
		}

		recovered := make([]byte, len(ct))
		dec.CryptBlocks(recovered, ct)
		if !bytes.Equal(recovered, pt) {
			t.Fatalf("block %d decrypt:\n  want: %x\n  got:  %x", i+1, pt, recovered)
		}
	}
}

// TestKAT_CTR_Kuznechik verifies CTR mode against GOST R 34.13-2015, A.1.2.
// IV = 1234567890abcef0 || 00...00 (left half is nonce, right half is counter).
func TestKAT_CTR_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	// Full block-size IV: 8-byte nonce in left half, 8-byte zero counter in right half.
	iv := mustHex("1234567890abcef00000000000000000")

	// Concatenate all plaintext blocks.
	var plaintext []byte
	for _, pt := range kuznechikKATPT {
		plaintext = append(plaintext, pt...)
	}

	// Expected concatenated ciphertext.
	expectedCT := mustHex(
		"f195d8bec10ed1dbd57b5fa240bda1b8" +
			"85eee733f6a13e5df33ce4b33c45dee4" +
			"a5eae88be6356ed3d5e877f13564a3a5" +
			"cb91fab1f20cbab6d1c6d15820bdba73",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCTR(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CTR encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	// Verify decryption (CTR is symmetric).
	recovered := make([]byte, len(ciphertext))
	NewCTR(b, iv).XORKeyStream(recovered, ciphertext)

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CTR decrypt:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

// TestKAT_CTR_Magma verifies CTR mode against GOST R 34.13-2015, A.2.2.
// IV = 12345678 || 00000000 (left half is nonce, right half is counter).
func TestKAT_CTR_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	// Full block-size IV: 4-byte nonce in left half, 4-byte zero counter in right half.
	iv := mustHex("1234567800000000")

	// Concatenate all plaintext blocks.
	var plaintext []byte
	for _, pt := range magmaKATPT {
		plaintext = append(plaintext, pt...)
	}

	// Expected concatenated ciphertext.
	expectedCT := mustHex(
		"4e98110c97b7b93c" +
			"3e250d93d6e85d69" +
			"136d868807b2dbef" +
			"568eb680ab52a12d",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCTR(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CTR encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	// Verify decryption (CTR is symmetric).
	recovered := make([]byte, len(ciphertext))
	NewCTR(b, iv).XORKeyStream(recovered, ciphertext)

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CTR decrypt:\n  want: %x\n  got:  %x", plaintext, recovered)
	}
}

// TestKAT_MAC_Kuznechik verifies CMAC (MAC) against GOST R 34.13-2015, A.1.6.
// MAC is truncated to s=64 bits (8 bytes).
func TestKAT_MAC_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate all plaintext blocks as MAC input.
	var data []byte
	for _, pt := range kuznechikKATPT {
		data = append(data, pt...)
	}

	expectedMAC := mustHex("336f4d296059fbe3")

	mac, err := NewMAC(b, 8) // s=64 bits = 8 bytes
	if err != nil {
		t.Fatal(err)
	}
	mac.Write(data)
	tag := mac.Sum(nil)

	if !bytes.Equal(tag, expectedMAC) {
		t.Fatalf("MAC:\n  want: %x\n  got:  %x", expectedMAC, tag)
	}
}

// TestKAT_MAC_Magma verifies CMAC (MAC) against GOST R 34.13-2015, A.2.6.
// MAC is truncated to s=32 bits (4 bytes).
func TestKAT_MAC_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate all plaintext blocks as MAC input.
	var data []byte
	for _, pt := range magmaKATPT {
		data = append(data, pt...)
	}

	expectedMAC := mustHex("154e7210")

	mac, err := NewMAC(b, 4) // s=32 bits = 4 bytes
	if err != nil {
		t.Fatal(err)
	}
	mac.Write(data)
	tag := mac.Sum(nil)

	if !bytes.Equal(tag, expectedMAC) {
		t.Fatalf("MAC:\n  want: %x\n  got:  %x", expectedMAC, tag)
	}
}

// TestKAT_OFB_Kuznechik verifies OFB mode against GOST R 34.13-2015, A.1.3.
// m=2n=256, IV is 32 bytes.
func TestKAT_OFB_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

	var plaintext []byte
	for _, pt := range kuznechikKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"81800a59b1842b24ff1f795e897abd95" +
			"ed5b47a7048cfab48fb521369d9326bf" +
			"66a257ac3ca0b8b1c80fe7fc10288a13" +
			"203ebbc066138660a0292243f6903150",
	)

	ciphertext := make([]byte, len(plaintext))
	NewOFB(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("OFB encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewOFB(b, iv).XORKeyStream(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("OFB decrypt mismatch")
	}
}

// TestKAT_OFB_Magma verifies OFB mode against GOST R 34.13-2015, A.2.3.
// m=2n=128, IV is 16 bytes.
func TestKAT_OFB_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcdef234567890abcdef1")

	var plaintext []byte
	for _, pt := range magmaKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"db37e0e266903c83" +
			"0d46644c1f9a089c" +
			"a0f83062430e327e" +
			"c824efb8bd4fdb05",
	)

	ciphertext := make([]byte, len(plaintext))
	NewOFB(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("OFB encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewOFB(b, iv).XORKeyStream(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("OFB decrypt mismatch")
	}
}

// TestKAT_CBC_Kuznechik verifies CBC mode against GOST R 34.13-2015, A.1.4.
// m=2n=256, IV is 32 bytes.
func TestKAT_CBC_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

	var plaintext []byte
	for _, pt := range kuznechikKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"689972d4a085fa4d90e52e3d6d7dcc27" +
			"2826e661b478eca6af1e8e448d5ea5ac" +
			"fe7babf1e91999e85640e8b0f49d90d0" +
			"167688065a895c631a2d9a1560b63970",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCBCEncrypter(b, iv).CryptBlocks(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CBC encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewCBCDecrypter(b, iv).CryptBlocks(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CBC decrypt mismatch")
	}
}

// TestKAT_CBC_Magma verifies CBC mode against GOST R 34.13-2015, A.2.4.
// m=3n=192, IV is 24 bytes.
func TestKAT_CBC_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcdef234567890abcdef134567890abcdef12")

	var plaintext []byte
	for _, pt := range magmaKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"96d1b05eea683919" +
			"aff76129abb937b9" +
			"5058b4a1c4bc0019" +
			"20b78b1a7cd7e667",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCBCEncrypter(b, iv).CryptBlocks(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CBC encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewCBCDecrypter(b, iv).CryptBlocks(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CBC decrypt mismatch")
	}
}

// TestKAT_CFB_Kuznechik verifies CFB mode against GOST R 34.13-2015, A.1.5.
// m=2n=256, IV is 32 bytes.
func TestKAT_CFB_Kuznechik(t *testing.T) {
	b, err := gost341215.NewKuznechik(kuznechikKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")

	var plaintext []byte
	for _, pt := range kuznechikKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"81800a59b1842b24ff1f795e897abd95" +
			"ed5b47a7048cfab48fb521369d9326bf" +
			"79f2a8eb5cc68d38842d264e97a238b5" +
			"4ffebecd4e922de6c75bd9dd44fbf4d1",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCFBEncrypter(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CFB encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewCFBDecrypter(b, iv).XORKeyStream(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CFB decrypt mismatch")
	}
}

// TestKAT_CFB_Magma verifies CFB mode against GOST R 34.13-2015, A.2.5.
// m=2n=128, IV is 16 bytes.
func TestKAT_CFB_Magma(t *testing.T) {
	b, err := gost341215.NewMagma(magmaKATKey)
	if err != nil {
		t.Fatal(err)
	}

	iv := mustHex("1234567890abcdef234567890abcdef1")

	var plaintext []byte
	for _, pt := range magmaKATPT {
		plaintext = append(plaintext, pt...)
	}

	expectedCT := mustHex(
		"db37e0e266903c83" +
			"0d46644c1f9a089c" +
			"24bdd2035315d38b" +
			"bcc0321421075505",
	)

	ciphertext := make([]byte, len(plaintext))
	NewCFBEncrypter(b, iv).XORKeyStream(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCT) {
		t.Fatalf("CFB encrypt:\n  want: %x\n  got:  %x", expectedCT, ciphertext)
	}

	recovered := make([]byte, len(ciphertext))
	NewCFBDecrypter(b, iv).XORKeyStream(recovered, ciphertext)
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("CFB decrypt mismatch")
	}
}
