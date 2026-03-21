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
	"encoding/hex"
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

// TestKAT_VKO256 verifies VKO KEK-256 against RFC 7836 Appendix B, Test 7.
// Uses 512-bit curve id-tc26-gost-3410-12-512-paramSetA.
func TestKAT_VKO256(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }

	curve := gost341012.Curve512ParamSetA()

	// Party A
	privA, err := gost341012.NewPrivateKey(curve,
		h("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"))
	if err != nil {
		t.Fatal(err)
	}
	pubA, err := gost341012.NewPublicKey(curve,
		h("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"))
	if err != nil {
		t.Fatal(err)
	}

	// Party B
	privB, err := gost341012.NewPrivateKey(curve,
		h("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"))
	if err != nil {
		t.Fatal(err)
	}
	pubB, err := gost341012.NewPublicKey(curve,
		h("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"))
	if err != nil {
		t.Fatal(err)
	}

	// UKM is LE in the RFC; reverse to get big-endian for big.Int.
	ukmLE := h("1d80603c8544c727")
	ukmBE := make([]byte, len(ukmLE))
	for i, j := 0, len(ukmLE)-1; j >= 0; i, j = i+1, j-1 {
		ukmBE[i] = ukmLE[j]
	}
	ukm := new(big.Int).SetBytes(ukmBE)

	wantKEK := h("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")

	kekA, err := KEK256(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK256 A->B: %v", err)
	}
	kekB, err := KEK256(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("KEK256 B->A: %v", err)
	}

	if !bytes.Equal(kekA, kekB) {
		t.Fatalf("KEK256 asymmetry:\n  A->B: %x\n  B->A: %x", kekA, kekB)
	}
	if !bytes.Equal(kekA, wantKEK) {
		t.Fatalf("KEK256 KAT:\n  got:  %x\n  want: %x", kekA, wantKEK)
	}
}

// TestKAT_VKO512 verifies VKO KEK-512 against RFC 7836 Appendix B, Test 8.
func TestKAT_VKO512(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }

	curve := gost341012.Curve512ParamSetA()

	privA, _ := gost341012.NewPrivateKey(curve,
		h("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"))
	pubB, _ := gost341012.NewPublicKey(curve,
		h("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"))

	ukmLE := h("1d80603c8544c727")
	ukmBE := make([]byte, len(ukmLE))
	for i, j := 0, len(ukmLE)-1; j >= 0; i, j = i+1, j-1 {
		ukmBE[i] = ukmLE[j]
	}
	ukm := new(big.Int).SetBytes(ukmBE)

	wantKEK := h("79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")

	kek, err := KEK512(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("KEK512: %v", err)
	}
	if !bytes.Equal(kek, wantKEK) {
		t.Fatalf("KEK512 KAT:\n  got:  %x\n  want: %x", kek, wantKEK)
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
