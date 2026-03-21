// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341112

import (
	"encoding/hex"
	"hash"
	"testing"
)

// Test vectors from ГОСТ Р 34.11-2012 (Appendix A).
var testVectors = []struct {
	name    string
	message string // hex-encoded
	hash256 string // hex-encoded expected Stribog-256
	hash512 string // hex-encoded expected Stribog-512
}{
	{
		name:    "M1",
		message: "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132",
		hash256: "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
		hash512: "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
	},
	{
		name:    "M2",
		message: "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb",
		hash256: "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50",
		hash512: "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28",
	},
}

func TestNew512(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			msg, err := hex.DecodeString(tv.message)
			if err != nil {
				t.Fatal(err)
			}
			h := New512()
			h.Write(msg)
			got := hex.EncodeToString(h.Sum(nil))
			if got != tv.hash512 {
				t.Errorf("Stribog-512(%s):\n  got  %s\n  want %s", tv.name, got, tv.hash512)
			}
		})
	}
}

func TestNew256(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			msg, err := hex.DecodeString(tv.message)
			if err != nil {
				t.Fatal(err)
			}
			h := New256()
			h.Write(msg)
			got := hex.EncodeToString(h.Sum(nil))
			if got != tv.hash256 {
				t.Errorf("Stribog-256(%s):\n  got  %s\n  want %s", tv.name, got, tv.hash256)
			}
		})
	}
}

func TestReset(t *testing.T) {
	msg, _ := hex.DecodeString(testVectors[0].message)

	h := New512()
	h.Write(msg)
	first := hex.EncodeToString(h.Sum(nil))

	h.Reset()
	h.Write(msg)
	second := hex.EncodeToString(h.Sum(nil))

	if first != second {
		t.Errorf("Reset: hash differs after reset:\n  first  %s\n  second %s", first, second)
	}
}

func TestSumAppend(t *testing.T) {
	msg, _ := hex.DecodeString(testVectors[0].message)
	prefix := []byte("prefix")

	h := New256()
	h.Write(msg)
	result := h.Sum(prefix)

	if string(result[:6]) != "prefix" {
		t.Error("Sum did not preserve the prefix")
	}
	got := hex.EncodeToString(result[6:])
	if got != testVectors[0].hash256 {
		t.Errorf("Sum with prefix:\n  got  %s\n  want %s", got, testVectors[0].hash256)
	}
}

func TestSizeAndBlockSize(t *testing.T) {
	h256 := New256()
	h512 := New512()

	if h256.Size() != 32 {
		t.Errorf("New256().Size() = %d, want 32", h256.Size())
	}
	if h512.Size() != 64 {
		t.Errorf("New512().Size() = %d, want 64", h512.Size())
	}
	if h256.BlockSize() != 64 {
		t.Errorf("New256().BlockSize() = %d, want 64", h256.BlockSize())
	}
	if h512.BlockSize() != 64 {
		t.Errorf("New512().BlockSize() = %d, want 64", h512.BlockSize())
	}
}

func TestIncrementalWrite(t *testing.T) {
	msg, _ := hex.DecodeString(testVectors[0].message)
	want := testVectors[0].hash512

	// Write one byte at a time.
	h := New512()
	for _, b := range msg {
		h.Write([]byte{b})
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("Incremental write:\n  got  %s\n  want %s", got, want)
	}
}

func TestEmptyMessage(t *testing.T) {
	// Empty message test — hash of zero-length input.
	h512 := New512()
	h512.Write(nil)
	sum512 := hex.EncodeToString(h512.Sum(nil))

	h256 := New256()
	h256.Write(nil)
	sum256 := hex.EncodeToString(h256.Sum(nil))

	// Just verify it produces a deterministic result (no crash) and correct length.
	if len(sum512) != 128 {
		t.Errorf("Empty 512: expected 128 hex chars, got %d", len(sum512))
	}
	if len(sum256) != 64 {
		t.Errorf("Empty 256: expected 64 hex chars, got %d", len(sum256))
	}
}

func TestHashInterface(t *testing.T) {
	var _ hash.Hash = New256()
	var _ hash.Hash = New512()
}
