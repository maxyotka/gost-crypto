// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341012_test

import (
	"crypto/rand"
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341012"
	"github.com/maxyotka/gost-crypto/gost341112"
)

// ExampleGenerateKey demonstrates signing and verification with the
// 256-bit curve paramSetA.
func ExampleGenerateKey() {
	curve := gost341012.CurveParamSetA()

	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	digest := gost341112.Sum256([]byte("message"))

	sig, err := priv.SignDigest(digest[:], rand.Reader)
	if err != nil {
		panic(err)
	}

	ok, err := pub.VerifyDigest(digest[:], sig)
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output: true
}

// ExampleCurve512ParamSetA demonstrates signing with the 512-bit curve.
func ExampleCurve512ParamSetA() {
	curve := gost341012.Curve512ParamSetA()

	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	digest := gost341112.Sum512([]byte("message"))

	sig, err := priv.SignDigest(digest[:], rand.Reader)
	if err != nil {
		panic(err)
	}

	ok, _ := pub.VerifyDigest(digest[:], sig)
	fmt.Println(ok, len(sig))
	// Output: true 128
}
