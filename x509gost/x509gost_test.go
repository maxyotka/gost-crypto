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
	"encoding/pem"
	"testing"
	"time"

	"github.com/maxyotka/gost-crypto/gost341012"
)

func TestCreateSelfSigned256(t *testing.T) {
	curve := gost341012.CurveParamSetA()
	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	subject := pkix.Name{
		CommonName:   "Test GOST Certificate",
		Organization: []string{"Test Org"},
		Country:      []string{"RU"},
	}

	now := time.Now()
	der, err := CreateSelfSigned(priv, pub, subject, now, now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateSelfSigned: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("empty certificate")
	}

	// Should be valid DER — encode to PEM to verify structure.
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if len(pemBlock) == 0 {
		t.Fatal("PEM encoding failed")
	}

	t.Logf("Certificate size: %d bytes DER, %d bytes PEM", len(der), len(pemBlock))
}

func TestCreateSelfSigned512(t *testing.T) {
	curve := gost341012.Curve512ParamSetA()
	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	subject := pkix.Name{
		CommonName:   "Test GOST-512 Certificate",
		Organization: []string{"Test Org"},
		Country:      []string{"RU"},
	}

	now := time.Now()
	der, err := CreateSelfSigned(priv, pub, subject, now, now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateSelfSigned 512: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("empty certificate")
	}

	t.Logf("512-bit certificate size: %d bytes DER", len(der))
}

func TestCryptoSigner(t *testing.T) {
	curve := gost341012.CurveParamSetA()
	priv, _, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}

	// Use crypto.Signer interface.
	sig, err := priv.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("crypto.Signer Sign: %v", err)
	}

	// Verify via PublicKey.
	pub := priv.Public().(*gost341012.PublicKey)
	ok, err := pub.VerifyDigest(digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !ok {
		t.Fatal("crypto.Signer signature failed verification")
	}
}

func TestOIDLookup(t *testing.T) {
	curves := []struct {
		name string
		c    *gost341012.Curve
	}{
		{"256-A", gost341012.CurveParamSetA()},
		{"256-B", gost341012.CurveParamSetB()},
		{"512-A", gost341012.Curve512ParamSetA()},
		{"512-C", gost341012.Curve512ParamSetC()},
	}

	for _, tc := range curves {
		oid := gost341012.OIDForCurve(tc.c)
		if oid == nil {
			t.Fatalf("OIDForCurve(%s) returned nil", tc.name)
		}

		back := gost341012.CurveByOID(oid)
		if back == nil {
			t.Fatalf("CurveByOID for %s returned nil", tc.name)
		}

		if back.P.Cmp(tc.c.P) != 0 {
			t.Fatalf("CurveByOID roundtrip failed for %s", tc.name)
		}
	}
}
