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
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

// errReader is an io.Reader that always returns an error.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errors.New("synthetic read failure") }

func TestGenerateKey_NilInputs(t *testing.T) {
	if _, _, err := GenerateKey(nil, rand.Reader); err == nil {
		t.Error("expected error for nil curve")
	}
	if _, _, err := GenerateKey(CurveParamSetA(), nil); err == nil {
		t.Error("expected error for nil random")
	}
}

func TestGenerateKey_RandFailure(t *testing.T) {
	if _, _, err := GenerateKey(CurveParamSetA(), errReader{}); err == nil {
		t.Error("expected error from failing reader")
	}
}

// seqReader feeds pre-defined byte sequences; once all are consumed,
// falls back to a constant byte.
type seqReader struct {
	seqs [][]byte
	idx  int
	tail byte
}

func (s *seqReader) Read(p []byte) (int, error) {
	if s.idx < len(s.seqs) {
		b := s.seqs[s.idx]
		s.idx++
		n := copy(p, b)
		for i := n; i < len(p); i++ {
			p[i] = s.tail
		}
		return len(p), nil
	}
	for i := range p {
		p[i] = s.tail
	}
	return len(p), nil
}

func TestSignDigest_ZeroKRetry(t *testing.T) {
	// First randInt call in sign returns 0, forcing the inner retry loop.
	c := CurveParamSetA()
	priv, _, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	byteLen := (c.Q.BitLen() + 7) / 8
	r := &seqReader{
		seqs: [][]byte{make([]byte, byteLen)},
		tail: 0x01,
	}
	if _, err := priv.SignDigest(make([]byte, 32), r); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
}

func TestGenerateKey_ZeroScalarRetry(t *testing.T) {
	// First randInt call returns 0 (all-zero bytes), forcing the d.Sign()==0
	// continue branch. The second call falls back to 0xFF bytes which yield
	// a valid scalar in range.
	c := CurveParamSetA()
	byteLen := (c.Q.BitLen() + 7) / 8
	r := &seqReader{
		seqs: [][]byte{make([]byte, byteLen)},
		tail: 0x01,
	}
	priv, pub, err := GenerateKey(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil || pub == nil {
		t.Error("expected non-nil keys")
	}
}

func TestPrivateKeyPublicKey_InvalidCases(t *testing.T) {
	if _, err := (&PrivateKey{}).PublicKey(); err == nil {
		t.Error("expected error for nil curve")
	}
	if _, err := (&PrivateKey{Curve: CurveParamSetA()}).PublicKey(); err == nil {
		t.Error("expected error for nil D")
	}
	if _, err := (&PrivateKey{Curve: CurveParamSetA(), D: big.NewInt(0)}).PublicKey(); err == nil {
		t.Error("expected error for zero D")
	}
}

func TestPrivateKeyPublicKey_PointAtInfinity(t *testing.T) {
	// d = q produces q*G = O (point at infinity), exercising that error.
	c := CurveParamSetA()
	priv := &PrivateKey{Curve: c, D: new(big.Int).Set(c.Q)}
	if _, err := priv.PublicKey(); err == nil {
		t.Error("expected point-at-infinity error")
	}
}

func TestPrivateKeyPublic_InvalidReturnsNil(t *testing.T) {
	priv := &PrivateKey{}
	if pub := priv.Public(); pub != nil {
		t.Error("expected nil public key for invalid private key")
	}
}

func TestPrivateKeyPublic_Valid(t *testing.T) {
	priv, _, err := GenerateKey(CurveParamSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if pub := priv.Public(); pub == nil {
		t.Error("expected non-nil public key")
	}
}

func TestNewPrivateKey_Errors(t *testing.T) {
	if _, err := NewPrivateKey(nil, make([]byte, 32)); err == nil {
		t.Error("expected nil curve error")
	}
	c := CurveParamSetA()
	if _, err := NewPrivateKey(c, make([]byte, 10)); err == nil {
		t.Error("expected bad size error")
	}
	// zero key is out of range
	if _, err := NewPrivateKey(c, make([]byte, 32)); err == nil {
		t.Error("expected out of range zero")
	}
	// key >= Q (all 0xFF)
	oor := make([]byte, 32)
	for i := range oor {
		oor[i] = 0xFF
	}
	if _, err := NewPrivateKey(c, oor); err == nil {
		t.Error("expected out of range >= Q")
	}
}

func TestNewPublicKey_Errors(t *testing.T) {
	if _, err := NewPublicKey(nil, make([]byte, 64)); err == nil {
		t.Error("expected nil curve error")
	}
	c := CurveParamSetA()
	if _, err := NewPublicKey(c, make([]byte, 10)); err == nil {
		t.Error("expected bad size error")
	}
	// Not on curve: all zeros
	if _, err := NewPublicKey(c, make([]byte, 64)); err == nil {
		t.Error("expected not on curve error")
	}
}

func TestNewPublicKey_Valid(t *testing.T) {
	c := CurveParamSetA()
	_, pub, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := pub.Raw()
	pub2, err := NewPublicKey(c, raw)
	if err != nil {
		t.Fatalf("valid raw public key failed: %v", err)
	}
	if pub2.X.Cmp(pub.X) != 0 || pub2.Y.Cmp(pub.Y) != 0 {
		t.Error("round-trip mismatch")
	}
}

func TestRandInt_ReaderError(t *testing.T) {
	if _, err := randInt(errReader{}, big.NewInt(1000)); err == nil {
		t.Error("expected reader error")
	}
}

func TestCurveByOID(t *testing.T) {
	cases := []struct {
		name string
		oid  asn1.ObjectIdentifier
		nil_ bool
	}{
		{"256A", OIDCurve256A, false},
		{"256B", OIDCurve256B, false},
		{"256C", OIDCurve256C, false},
		{"256D", OIDCurve256D, false},
		{"512A", OIDCurve512A, false},
		{"512B", OIDCurve512B, false},
		{"512C", OIDCurve512C, false},
		{"unknown", asn1.ObjectIdentifier{1, 2, 3, 4, 5}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CurveByOID(tc.oid)
			if tc.nil_ && got != nil {
				t.Error("expected nil")
			}
			if !tc.nil_ && got == nil {
				t.Error("expected curve")
			}
		})
	}
}

func TestOIDForCurve(t *testing.T) {
	if OIDForCurve(nil) != nil {
		t.Error("expected nil for nil curve")
	}
	curves := []*Curve{
		CurveParamSetA(), CurveParamSetB(), CurveParamSetC(), CurveParamSetD(),
		Curve512ParamSetA(), Curve512ParamSetB(), Curve512ParamSetC(),
	}
	for _, c := range curves {
		if OIDForCurve(c) == nil {
			t.Errorf("expected OID for known curve")
		}
	}
	// Unknown curve
	unk := &Curve{P: big.NewInt(97), X: big.NewInt(3)}
	if OIDForCurve(unk) != nil {
		t.Error("expected nil for unknown curve")
	}
}

func TestSignDigest_Errors(t *testing.T) {
	// nil curve
	priv := &PrivateKey{}
	if _, err := priv.SignDigest([]byte("digest"), rand.Reader); err == nil {
		t.Error("expected error for nil curve")
	}
	// invalid D
	priv2 := &PrivateKey{Curve: CurveParamSetA()}
	if _, err := priv2.SignDigest([]byte("digest"), rand.Reader); err == nil {
		t.Error("expected error for nil D")
	}
	// bad reader
	goodPriv, _, _ := GenerateKey(CurveParamSetA(), rand.Reader)
	if _, err := goodPriv.SignDigest(make([]byte, 32), errReader{}); err == nil {
		t.Error("expected error from failing reader")
	}
}

func TestSignDigest_ZeroEToOne(t *testing.T) {
	// Digest that is a multiple of Q (e == 0 branch). Use q itself.
	c := CurveParamSetA()
	priv := &PrivateKey{Curve: c, D: big.NewInt(123456789)}
	digest := c.Q.Bytes()
	if _, err := priv.SignDigest(digest, rand.Reader); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
}

func TestSignDigestInternal_FixedKBadPoint(t *testing.T) {
	// Use fixed k = 0 to force point at infinity.
	c := CurveParamSetA()
	priv := &PrivateKey{Curve: c, D: big.NewInt(1)}
	if _, err := priv.signDigestInternal(make([]byte, 32), rand.Reader, big.NewInt(0)); err == nil {
		t.Error("expected error for fixed k producing point at infinity")
	}
}

func TestVerifyDigest_Errors(t *testing.T) {
	// Nil curve
	pub := &PublicKey{}
	if _, err := pub.VerifyDigest(make([]byte, 32), make([]byte, 64)); err == nil {
		t.Error("expected nil curve error")
	}
	// Nil X/Y
	pub2 := &PublicKey{Curve: CurveParamSetA()}
	if _, err := pub2.VerifyDigest(make([]byte, 32), make([]byte, 64)); err == nil {
		t.Error("expected nil coordinates error")
	}
	// Bad signature size
	priv, gpub, err := GenerateKey(CurveParamSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gpub.VerifyDigest(make([]byte, 32), make([]byte, 10)); err == nil {
		t.Error("expected bad signature size")
	}
	// s out of range (zero)
	if ok, _ := gpub.VerifyDigest(make([]byte, 32), make([]byte, 64)); ok {
		t.Error("expected invalid for zero signature")
	}
	// s out of range (>= q): set s bytes to q
	c := gpub.Curve
	sig := make([]byte, 64)
	qBytes := bigIntToLE(c.Q, 32)
	copy(sig[:32], qBytes)
	// r = 1
	sig[32] = 1
	if ok, _ := gpub.VerifyDigest(make([]byte, 32), sig); ok {
		t.Error("expected invalid for s >= q")
	}
	// r out of range: s = 1, r = q
	sig2 := make([]byte, 64)
	sig2[0] = 1
	copy(sig2[32:], qBytes)
	if ok, _ := gpub.VerifyDigest(make([]byte, 32), sig2); ok {
		t.Error("expected invalid for r >= q")
	}
	// Verify zero e to ensure e==0 branch via digest = q
	sigValid, err := priv.SignDigest(c.Q.Bytes(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := gpub.VerifyDigest(c.Q.Bytes(), sigValid); err != nil || !ok {
		t.Errorf("verify should succeed: ok=%v err=%v", ok, err)
	}
}

func TestVerifyDigest_PointAtInfinity(t *testing.T) {
	// Craft a signature where s ≡ r*d (mod q) so that
	// (s*v - r*v*d) ≡ 0 and z1*G + z2*Q is the point at infinity.
	c := CurveParamSetA()
	d := big.NewInt(42)
	priv := &PrivateKey{Curve: c, D: d}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	r := big.NewInt(7)
	s := new(big.Int).Mul(r, d)
	s.Mod(s, c.Q)
	size := c.ByteSize()
	sig := make([]byte, 2*size)
	copy(sig[:size], bigIntToLE(s, size))
	copy(sig[size:], bigIntToLE(r, size))
	ok, err := pub.VerifyDigest(make([]byte, 32), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected verification failure for infinity result")
	}
	_ = bytes.Equal // keep import
	_ = io.EOF
}

func TestIsOnCurve_Nil(t *testing.T) {
	c := CurveParamSetA()
	if c.IsOnCurve(nil, big.NewInt(1)) {
		t.Error("nil x should not be on curve")
	}
	if c.IsOnCurve(big.NewInt(1), nil) {
		t.Error("nil y should not be on curve")
	}
}

func TestPointAdd_IdentityAndInverses(t *testing.T) {
	c := CurveParamSetA()
	// identity + identity
	x, y := c.pointAdd(nil, nil, nil, nil)
	if x != nil || y != nil {
		t.Error("expected infinity")
	}
	// identity + P
	x, y = c.pointAdd(nil, nil, c.X, c.Y)
	if x.Cmp(c.X) != 0 {
		t.Error("expected P")
	}
	// P + identity
	x, y = c.pointAdd(c.X, c.Y, nil, nil)
	if x.Cmp(c.X) != 0 {
		t.Error("expected P")
	}
	// P + (-P) = infinity. -P has y = -y mod p.
	negY := new(big.Int).Sub(c.P, c.Y)
	x, y = c.pointAdd(c.X, c.Y, c.X, negY)
	if x != nil || y != nil {
		t.Error("expected point at infinity")
	}
	// P + P via pointAdd (calls pointDouble)
	x2, y2 := c.pointAdd(c.X, c.Y, c.X, c.Y)
	// Should equal pointDouble(P)
	dx, dy := c.pointDouble(c.X, c.Y)
	if x2.Cmp(dx) != 0 || y2.Cmp(dy) != 0 {
		t.Error("add(P,P) != double(P)")
	}
}

func TestPointDouble_Edge(t *testing.T) {
	c := CurveParamSetA()
	// nil input
	x, y := c.pointDouble(nil, nil)
	if x != nil || y != nil {
		t.Error("expected infinity")
	}
	// y = 0
	x, y = c.pointDouble(big.NewInt(1), big.NewInt(0))
	if x != nil || y != nil {
		t.Error("expected infinity when y=0")
	}
}
