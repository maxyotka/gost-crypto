// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341315_test

import (
	"bytes"
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341215"
	"github.com/maxyotka/gost-crypto/gost341315"
)

// ExampleNewCBCEncrypter demonstrates a CBC encrypt/decrypt roundtrip
// with Kuznyechik.
func ExampleNewCBCEncrypter() {
	key := make([]byte, gost341215.KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	block, _ := gost341215.NewKuznechik(key)

	iv := make([]byte, block.BlockSize())
	plaintext := bytes.Repeat([]byte{0x42}, 2*block.BlockSize())

	enc := gost341315.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	enc.CryptBlocks(ciphertext, plaintext)

	dec := gost341315.NewCBCDecrypter(block, iv)
	recovered := make([]byte, len(ciphertext))
	dec.CryptBlocks(recovered, ciphertext)

	fmt.Println(bytes.Equal(plaintext, recovered))
	// Output: true
}

// ExampleNewCTR shows CTR mode as a streaming cipher.Stream.
func ExampleNewCTR() {
	key := make([]byte, gost341215.KuznechikKeySize)
	block, _ := gost341215.NewKuznechik(key)

	iv := make([]byte, block.BlockSize())
	iv[0] = 0x01

	stream := gost341315.NewCTR(block, iv)
	plaintext := []byte("stream-encrypted message")
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Reset stream for decryption.
	stream = gost341315.NewCTR(block, iv)
	recovered := make([]byte, len(ciphertext))
	stream.XORKeyStream(recovered, ciphertext)

	fmt.Println(string(recovered))
	// Output: stream-encrypted message
}

// ExampleNewMAC computes a GOST MAC tag over a message.
func ExampleNewMAC() {
	key := make([]byte, gost341215.KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	block, _ := gost341215.NewKuznechik(key)

	mac, err := gost341315.NewMAC(block, block.BlockSize())
	if err != nil {
		panic(err)
	}
	mac.Write([]byte("authenticated message"))
	fmt.Println(len(mac.Sum(nil)))
	// Output: 16
}
