// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package mgm_test

import (
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341215"
	"github.com/maxyotka/gost-crypto/mgm"
)

// ExampleNewMGM shows an authenticated encryption roundtrip with
// Kuznyechik in MGM mode.
func ExampleNewMGM() {
	key := make([]byte, gost341215.KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	block, err := gost341215.NewKuznechik(key)
	if err != nil {
		panic(err)
	}

	aead, err := mgm.NewMGM(block, block.BlockSize())
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	nonce[0] = 0x11 // RFC 9058: MSB must be zero.

	plaintext := []byte("authenticated secret")
	aad := []byte("associated data")

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	recovered, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(recovered))
	// Output: authenticated secret
}
