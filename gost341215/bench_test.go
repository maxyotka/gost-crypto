// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import "testing"

func BenchmarkKuznechikEncrypt(b *testing.B) {
	key := make([]byte, KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, _ := NewKuznechik(key)
	src := make([]byte, KuznechikBlockSize)
	dst := make([]byte, KuznechikBlockSize)
	b.SetBytes(int64(KuznechikBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}

func BenchmarkKuznechikDecrypt(b *testing.B) {
	key := make([]byte, KuznechikKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, _ := NewKuznechik(key)
	src := make([]byte, KuznechikBlockSize)
	dst := make([]byte, KuznechikBlockSize)
	b.SetBytes(int64(KuznechikBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(dst, src)
	}
}

func BenchmarkMagmaEncrypt(b *testing.B) {
	key := make([]byte, MagmaKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, _ := NewMagma(key)
	src := make([]byte, MagmaBlockSize)
	dst := make([]byte, MagmaBlockSize)
	b.SetBytes(int64(MagmaBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}

func BenchmarkMagmaDecrypt(b *testing.B) {
	key := make([]byte, MagmaKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, _ := NewMagma(key)
	src := make([]byte, MagmaBlockSize)
	dst := make([]byte, MagmaBlockSize)
	b.SetBytes(int64(MagmaBlockSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(dst, src)
	}
}
