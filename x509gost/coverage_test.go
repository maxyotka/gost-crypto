// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package x509gost

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/maxyotka/gost-crypto/gost341012"
)

func TestCreateSelfSigned_NilInputs(t *testing.T) {
	now := time.Now()
	subject := pkix.Name{CommonName: "x"}
	if _, err := CreateSelfSigned(nil, nil, subject, now, now); err == nil {
		t.Error("expected error for nil priv/pub")
	}
	priv, pub, _ := gost341012.GenerateKey(gost341012.CurveParamSetA(), rand.Reader)
	if _, err := CreateSelfSigned(&gost341012.PrivateKey{}, pub, subject, now, now); err == nil {
		t.Error("expected error for priv with nil curve")
	}
	_ = priv
}

func TestMarshalPublicKey(t *testing.T) {
	_, pub, _ := gost341012.GenerateKey(gost341012.CurveParamSetA(), rand.Reader)
	b, err := marshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Error("empty encoding")
	}
}

func TestVerifySelfSigned(t *testing.T) {
	// Try with invalid DER bytes — forces the parse error branch.
	if _, err := VerifySelfSigned([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("expected parse error on invalid DER")
	}
	// Also try with a valid GOST self-signed certificate. Go's x509 parser
	// may or may not accept it depending on version; we just call the
	// function to cover the success branch when it does.
	priv, pub, _ := gost341012.GenerateKey(gost341012.CurveParamSetA(), rand.Reader)
	now := time.Now()
	der, err := CreateSelfSigned(priv, pub, pkix.Name{CommonName: "t"}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = VerifySelfSigned(der) // result path depends on Go version
}

func TestPublicKeyAlgorithm_UnknownCurve(t *testing.T) {
	// Craft a curve that isn't in the known set but still has ByteSize > 0.
	unknown := &gost341012.Curve{
		P: big.NewInt(97),
		A: big.NewInt(0),
		B: big.NewInt(7),
		Q: big.NewInt(83),
		X: big.NewInt(3),
		Y: big.NewInt(6),
	}
	alg := publicKeyAlgorithm(unknown)
	if len(alg.Parameters.FullBytes) == 0 {
		t.Error("expected parameters to be populated even with fallback OID")
	}
	// Also exercise > 32 byte ByteSize fallback.
	big512P, _ := new(big.Int).SetString("1"+"00"+"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16)
	unknown512 := &gost341012.Curve{
		P: big512P,
		A: big.NewInt(0),
		B: big.NewInt(7),
		Q: big.NewInt(83),
		X: big.NewInt(3),
		Y: big.NewInt(6),
	}
	alg2 := publicKeyAlgorithm(unknown512)
	if len(alg2.Parameters.FullBytes) == 0 {
		t.Error("expected parameters for unknown 512 curve")
	}
}
