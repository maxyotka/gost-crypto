// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package vko

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/maxyotka/gost-crypto/gost341012"
)

func TestSharedPoint_InvalidInputs(t *testing.T) {
	priv, pub, err := gost341012.GenerateKey(gost341012.CurveParamSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ukm := big.NewInt(1)

	if _, err := KEK256(nil, pub, ukm); err == nil {
		t.Error("expected error: nil priv")
	}
	if _, err := KEK256(&gost341012.PrivateKey{}, pub, ukm); err == nil {
		t.Error("expected error: no curve")
	}
	if _, err := KEK256(&gost341012.PrivateKey{Curve: priv.Curve}, pub, ukm); err == nil {
		t.Error("expected error: no D")
	}
	if _, err := KEK256(priv, nil, ukm); err == nil {
		t.Error("expected error: nil pub")
	}
	if _, err := KEK256(priv, &gost341012.PublicKey{Curve: priv.Curve}, ukm); err == nil {
		t.Error("expected error: no X/Y")
	}
	if _, err := KEK256(priv, pub, nil); err == nil {
		t.Error("expected error: nil ukm")
	}
	if _, err := KEK256(priv, pub, big.NewInt(0)); err == nil {
		t.Error("expected error: zero ukm")
	}
}

func TestSharedPoint_InfinityResult(t *testing.T) {
	// Construct ukm*d ≡ 0 (mod q) so scalar multiplication yields the
	// point at infinity.
	curve := gost341012.CurveParamSetA()
	_, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv := &gost341012.PrivateKey{Curve: curve, D: big.NewInt(1)}
	if _, err := KEK256(priv, pub, curve.Q); err == nil {
		t.Error("expected point-at-infinity error")
	}
}

func TestKEK512_Basic(t *testing.T) {
	priv, pub, err := gost341012.GenerateKey(gost341012.Curve512ParamSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := KEK512(priv, pub, big.NewInt(42))
	if err != nil {
		t.Fatal(err)
	}
	if len(kek) != 64 {
		t.Errorf("KEK512 length = %d; want 64", len(kek))
	}
}
