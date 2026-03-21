// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341112

import "testing"

func BenchmarkNew256(b *testing.B) {
	data := make([]byte, 64)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New256()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkNew512(b *testing.B) {
	data := make([]byte, 64)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New512()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkNew256_1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New256()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkNew512_1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New512()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkNew256_8KB(b *testing.B) {
	data := make([]byte, 8192)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New256()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkNew512_8KB(b *testing.B) {
	data := make([]byte, 8192)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New512()
		h.Write(data)
		h.Sum(nil)
	}
}
