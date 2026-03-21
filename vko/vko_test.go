// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package vko

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341012"
)

func generateKeyPair(t *testing.T) (*gost341012.PrivateKey, *gost341012.PublicKey) {
	t.Helper()
	curve := gost341012.CurveParamSetA()
	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, pub
}

func TestKEK256Roundtrip(t *testing.T) {
	privA, pubA := generateKeyPair(t)
	privB, pubB := generateKeyPair(t)

	ukm := big.NewInt(42)

	kekAB, err := KEK256(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK256(A→B): %v", err)
	}

	kekBA, err := KEK256(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("KEK256(B→A): %v", err)
	}

	if !bytes.Equal(kekAB, kekBA) {
		t.Fatalf("KEK256 mismatch:\n  A→B: %x\n  B→A: %x", kekAB, kekBA)
	}

	if len(kekAB) != 32 {
		t.Fatalf("KEK256 length = %d, want 32", len(kekAB))
	}
}

func TestKEK512Roundtrip(t *testing.T) {
	privA, pubA := generateKeyPair(t)
	privB, pubB := generateKeyPair(t)

	ukm := big.NewInt(42)

	kekAB, err := KEK512(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK512(A→B): %v", err)
	}

	kekBA, err := KEK512(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("KEK512(B→A): %v", err)
	}

	if !bytes.Equal(kekAB, kekBA) {
		t.Fatalf("KEK512 mismatch:\n  A→B: %x\n  B→A: %x", kekAB, kekBA)
	}

	if len(kekAB) != 64 {
		t.Fatalf("KEK512 length = %d, want 64", len(kekAB))
	}
}

func TestKEK256UKMOne(t *testing.T) {
	privA, pubA := generateKeyPair(t)
	privB, pubB := generateKeyPair(t)

	ukm := big.NewInt(1)

	kekAB, err := KEK256(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK256 with ukm=1: %v", err)
	}

	kekBA, err := KEK256(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("KEK256 with ukm=1: %v", err)
	}

	if !bytes.Equal(kekAB, kekBA) {
		t.Fatalf("KEK256 with ukm=1 mismatch:\n  A→B: %x\n  B→A: %x", kekAB, kekBA)
	}
}

func TestKEKZeroUKM(t *testing.T) {
	priv, pub := generateKeyPair(t)

	_, err := KEK256(priv, pub, big.NewInt(0))
	if err == nil {
		t.Fatal("KEK256 should reject zero ukm")
	}

	_, err = KEK512(priv, pub, big.NewInt(0))
	if err == nil {
		t.Fatal("KEK512 should reject zero ukm")
	}

	_, err = KEK256(priv, pub, nil)
	if err == nil {
		t.Fatal("KEK256 should reject nil ukm")
	}
}

func TestKEK256Deterministic(t *testing.T) {
	privA, _ := generateKeyPair(t)
	_, pubB := generateKeyPair(t)

	ukm := big.NewInt(12345)

	kek1, err := KEK256(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK256 first call: %v", err)
	}

	kek2, err := KEK256(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK256 second call: %v", err)
	}

	if !bytes.Equal(kek1, kek2) {
		t.Fatalf("KEK256 not deterministic:\n  call 1: %x\n  call 2: %x", kek1, kek2)
	}
}

func TestKEK512Deterministic(t *testing.T) {
	privA, _ := generateKeyPair(t)
	_, pubB := generateKeyPair(t)

	ukm := big.NewInt(99999)

	kek1, err := KEK512(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK512 first call: %v", err)
	}

	kek2, err := KEK512(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK512 second call: %v", err)
	}

	if !bytes.Equal(kek1, kek2) {
		t.Fatalf("KEK512 not deterministic:\n  call 1: %x\n  call 2: %x", kek1, kek2)
	}
}

func TestKEKDifferentUKMProducesDifferentKey(t *testing.T) {
	privA, _ := generateKeyPair(t)
	_, pubB := generateKeyPair(t)

	kek1, err := KEK256(privA, pubB, big.NewInt(1))
	if err != nil {
		t.Fatalf("KEK256 ukm=1: %v", err)
	}

	kek2, err := KEK256(privA, pubB, big.NewInt(2))
	if err != nil {
		t.Fatalf("KEK256 ukm=2: %v", err)
	}

	if bytes.Equal(kek1, kek2) {
		t.Fatal("KEK256 with different ukm should produce different keys")
	}
}

func TestKEKInvalidInputs(t *testing.T) {
	priv, pub := generateKeyPair(t)

	// nil private key
	if _, err := KEK256(nil, pub, big.NewInt(1)); err == nil {
		t.Fatal("expected error for nil private key")
	}

	// nil public key
	if _, err := KEK256(priv, nil, big.NewInt(1)); err == nil {
		t.Fatal("expected error for nil public key")
	}
}
