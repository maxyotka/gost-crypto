// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package vko_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/maxyotka/gost-crypto/gost341012"
	"github.com/maxyotka/gost-crypto/vko"
)

// ExampleKEK256 shows how two parties derive a shared 256-bit KEK
// from their own private key and the peer's public key.
func ExampleKEK256() {
	curve := gost341012.CurveParamSetA()

	alicePriv, alicePub, _ := gost341012.GenerateKey(curve, rand.Reader)
	bobPriv, bobPub, _ := gost341012.GenerateKey(curve, rand.Reader)

	ukm := big.NewInt(1) // user keying material, agreed out of band

	aliceKEK, err := vko.KEK256(alicePriv, bobPub, ukm)
	if err != nil {
		panic(err)
	}
	bobKEK, err := vko.KEK256(bobPriv, alicePub, ukm)
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(aliceKEK, bobKEK), len(aliceKEK))
	// Output: true 32
}
