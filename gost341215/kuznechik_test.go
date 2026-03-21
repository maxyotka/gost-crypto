// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 7801, Section 5.
func TestKuznechikEncryptRFC7801(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
	want, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")

	c, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, KuznechikBlockSize)
	c.Encrypt(ct, pt)

	if !bytes.Equal(ct, want) {
		t.Fatalf("Encrypt:\n got  %x\n want %x", ct, want)
	}
}

func TestKuznechikDecryptRFC7801(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	ct, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")
	want, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")

	c, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	pt := make([]byte, KuznechikBlockSize)
	c.Decrypt(pt, ct)

	if !bytes.Equal(pt, want) {
		t.Fatalf("Decrypt:\n got  %x\n want %x", pt, want)
	}
}

func TestKuznechikRoundKeys(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	c, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	kuz := c.(*kuznechik)

	roundKeys := [kuznechikRounds]string{
		"8899aabbccddeeff0011223344556677",
		"fedcba98765432100123456789abcdef",
		"db31485315694343228d6aef8cc78c44",
		"3d4553d8e9cfec6815ebadc40a9ffd04",
		"57646468c44a5e28d3e59246f429f1ac",
		"bd079435165c6432b532e82834da581b",
		"51e640757e8745de705727265a0098b1",
		"5a7925017b9fdd3ed72a91a22286f984",
		"bb44e25378c73123a5f32f73cdb6e517",
		"72e9dd7416bcf45b755dbaa88e4a4043",
	}

	for i, wantHex := range roundKeys {
		want, _ := hex.DecodeString(wantHex)
		if !bytes.Equal(kuz.enc[i][:], want) {
			t.Errorf("K%d:\n got  %x\n want %s", i+1, kuz.enc[i], wantHex)
		}
	}
}

func TestKuznechikRoundtrip(t *testing.T) {
	key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")

	c, err := NewKuznechik(key)
	if err != nil {
		t.Fatal(err)
	}

	ct := make([]byte, KuznechikBlockSize)
	c.Encrypt(ct, pt)

	got := make([]byte, KuznechikBlockSize)
	c.Decrypt(got, ct)

	if !bytes.Equal(got, pt) {
		t.Fatalf("Roundtrip failed:\n got  %x\n want %x", got, pt)
	}
}

func TestKuznechikInvalidKeySize(t *testing.T) {
	_, err := NewKuznechik(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}
