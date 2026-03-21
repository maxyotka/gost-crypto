// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215_test

import (
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341215"
)

func ExampleNewKuznechik() {
	key := make([]byte, gost341215.KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := gost341215.NewKuznechik(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ciphertext := make([]byte, gost341215.KuznechikBlockSize)
	c.Encrypt(ciphertext, plaintext)
	fmt.Printf("%x\n", ciphertext)
	// Output: cc378605bf71d86879150f7644b46a7f
}

func ExampleNewMagma() {
	key := make([]byte, gost341215.MagmaKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := gost341215.NewMagma(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	ciphertext := make([]byte, gost341215.MagmaBlockSize)
	c.Encrypt(ciphertext, plaintext)

	decrypted := make([]byte, gost341215.MagmaBlockSize)
	c.Decrypt(decrypted, ciphertext)
	fmt.Printf("%x\n", decrypted)
	// Output: deadbeefcafebabe
}
