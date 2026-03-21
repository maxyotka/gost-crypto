// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341012

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

// testCurve returns the RFC 7091 test curve (NOT paramSetA).
func testCurve() *Curve {
	return &Curve{
		P: mustHex("8000000000000000000000000000000000000000000000000000000000000431"),
		A: mustHex("7"),
		B: mustHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		Q: mustHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		X: mustHex("2"),
		Y: mustHex("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in test: " + err.Error())
	}
	return b
}

// TestKAT verifies signature generation with a known k against expected r and s
// from RFC 7091 Section 7.
func TestKAT(t *testing.T) {
	c := testCurve()

	d := mustHex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	priv := &PrivateKey{Curve: c, D: d}

	// Verify public key derivation.
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	wantPubX := mustHex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")
	wantPubY := mustHex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")
	if pub.X.Cmp(wantPubX) != 0 {
		t.Errorf("pub.X mismatch:\n  got  %064X\n  want %064X", pub.X, wantPubX)
	}
	if pub.Y.Cmp(wantPubY) != 0 {
		t.Errorf("pub.Y mismatch:\n  got  %064X\n  want %064X", pub.Y, wantPubY)
	}

	// Sign with fixed k.
	digest := mustDecodeHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	k := mustHex("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3")

	sig, err := priv.signDigestInternal(digest, nil, k)
	if err != nil {
		t.Fatalf("signDigestInternal: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length: got %d, want %d", len(sig), SignatureSize)
	}

	// Parse s and r from signature.
	gotS := leToBigInt(sig[:PrivateKeySize])
	gotR := leToBigInt(sig[PrivateKeySize:])

	wantR := mustHex("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	wantS := mustHex("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	if gotR.Cmp(wantR) != 0 {
		t.Errorf("r mismatch:\n  got  %064X\n  want %064X", gotR, wantR)
	}
	if gotS.Cmp(wantS) != 0 {
		t.Errorf("s mismatch:\n  got  %064X\n  want %064X", gotS, wantS)
	}

	// Verify the KAT signature.
	ok, err := pub.VerifyDigest(digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !ok {
		t.Error("KAT signature failed verification")
	}
}

// TestSignVerifyRoundtrip generates a key, signs, and verifies.
func TestSignVerifyRoundtrip(t *testing.T) {
	c := CurveParamSetA()
	priv, pub, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	ok, err := pub.VerifyDigest(digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !ok {
		t.Error("valid signature failed verification")
	}
}

// TestVerifyWrongKey checks that verification fails with a different public key.
func TestVerifyWrongKey(t *testing.T) {
	c := CurveParamSetA()
	priv1, _, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey 1: %v", err)
	}
	_, pub2, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig, err := priv1.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	ok, err := pub2.VerifyDigest(digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if ok {
		t.Error("signature verified with wrong public key")
	}
}

// TestVerifyTamperedDigest checks that verification fails when digest is changed.
func TestVerifyTamperedDigest(t *testing.T) {
	c := CurveParamSetA()
	priv, pub, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	// Tamper with digest.
	tampered := make([]byte, len(digest))
	copy(tampered, digest)
	tampered[0] ^= 0xFF

	ok, err := pub.VerifyDigest(tampered, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if ok {
		t.Error("signature verified with tampered digest")
	}
}

// TestRawKeyRoundtrip checks that PrivateKey and PublicKey survive Raw/New.
func TestRawKeyRoundtrip(t *testing.T) {
	c := CurveParamSetA()
	priv, pub, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Private key round-trip.
	privRaw := priv.Raw()
	if len(privRaw) != PrivateKeySize {
		t.Fatalf("priv.Raw() length: got %d, want %d", len(privRaw), PrivateKeySize)
	}
	priv2, err := NewPrivateKey(c, privRaw)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if priv.D.Cmp(priv2.D) != 0 {
		t.Errorf("private key round-trip: D mismatch")
	}

	// Public key round-trip.
	pubRaw := pub.Raw()
	if len(pubRaw) != PublicKeySize {
		t.Fatalf("pub.Raw() length: got %d, want %d", len(pubRaw), PublicKeySize)
	}
	pub2, err := NewPublicKey(c, pubRaw)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	if pub.X.Cmp(pub2.X) != 0 || pub.Y.Cmp(pub2.Y) != 0 {
		t.Errorf("public key round-trip: point mismatch")
	}
}

// TestSignIsRandomized verifies that two signatures of the same digest differ.
func TestSignIsRandomized(t *testing.T) {
	c := CurveParamSetA()
	priv, _, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	sig1, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest 1: %v", err)
	}
	sig2, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest 2: %v", err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Error("two signatures of the same digest are identical — sign is not randomized")
	}
}

// TestCurveBasePointOnCurve verifies that the base point of paramSetA is on the curve.
func TestCurveBasePointOnCurve(t *testing.T) {
	c := CurveParamSetA()
	if !c.IsOnCurve(c.X, c.Y) {
		t.Error("paramSetA base point is not on the curve")
	}
}

// TestCurveBasePointOrder verifies that Q * G = point at infinity.
func TestCurveBasePointOrder(t *testing.T) {
	c := CurveParamSetA()
	x, y := c.ScalarBaseMult(c.Q)
	if x != nil || y != nil {
		t.Error("Q * G is not the point at infinity")
	}
}

// TestTestCurveBasePointOnCurve verifies that the test curve base point is valid.
func TestTestCurveBasePointOnCurve(t *testing.T) {
	c := testCurve()
	if !c.IsOnCurve(c.X, c.Y) {
		t.Error("test curve base point is not on the curve")
	}
}

// TestKATPublicKeyOnCurve verifies that the KAT public key lies on the test curve.
func TestKATPublicKeyOnCurve(t *testing.T) {
	c := testCurve()
	x := mustHex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")
	y := mustHex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")
	if !c.IsOnCurve(x, y) {
		t.Error("KAT public key is not on the test curve")
	}
}

// TestSignatureSize checks that all signatures have the correct length.
func TestSignatureSize(t *testing.T) {
	c := testCurve()
	d := mustHex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	priv := &PrivateKey{Curve: c, D: d}

	digest := mustDecodeHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	sig, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("len(sig) = %d, want 64", len(sig))
	}
}

// TestLEConversions tests the little-endian conversion helpers.
func TestLEConversions(t *testing.T) {
	v := new(big.Int).SetInt64(0x0102030405060708)
	le := bigIntToLE(v, 8)
	want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(le, want) {
		t.Errorf("bigIntToLE: got %x, want %x", le, want)
	}
	back := leToBigInt(le)
	if back.Cmp(v) != 0 {
		t.Errorf("leToBigInt round-trip: got %x, want %x", back, v)
	}
}
