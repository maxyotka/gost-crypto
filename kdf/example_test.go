// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package kdf_test

import (
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341112"
	"github.com/maxyotka/gost-crypto/gost341215"
	"github.com/maxyotka/gost-crypto/kdf"
)

// ExampleKDF256 derives a 256-bit key from a master key using
// KDF_GOSTR3411_2012_256 (R 50.1.113-2016).
func ExampleKDF256() {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}

	derived := kdf.KDF256(master, []byte("label"), []byte("seed"))
	fmt.Println(len(derived))
	// Output: 32
}

// ExamplePBKDF2 derives a key from a password using PBKDF2 over
// HMAC-Stribog-256 (R 50.1.111-2016).
func ExamplePBKDF2() {
	key := kdf.PBKDF2(
		[]byte("correct horse battery staple"),
		[]byte("NaCl"),
		4096,
		32,
		gost341112.New256,
	)
	fmt.Println(len(key))
	// Output: 32
}

// ExampleWrapKey wraps and unwraps a 256-bit content-encryption key
// with a Kuznyechik key-encryption key.
func ExampleWrapKey() {
	kekBytes := make([]byte, gost341215.KuznechikKeySize)
	for i := range kekBytes {
		kekBytes[i] = byte(i)
	}
	kek, _ := gost341215.NewKuznechik(kekBytes)

	cek := make([]byte, gost341215.KuznechikKeySize)
	for i := range cek {
		cek[i] = byte(0xA0 + i)
	}

	wrapped, err := kdf.WrapKey(kek, cek)
	if err != nil {
		panic(err)
	}

	unwrapped, err := kdf.UnwrapKey(kek, wrapped)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(unwrapped) == len(cek))
	// Output: true
}
