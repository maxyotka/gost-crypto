// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import "testing"

func TestNewKuznechik_BadKeySize(t *testing.T) {
	if _, err := NewKuznechik(make([]byte, 10)); err == nil {
		t.Error("expected error for short key")
	}
}

func TestNewMagma_BadKeySize(t *testing.T) {
	if _, err := NewMagma(make([]byte, 10)); err == nil {
		t.Error("expected error for short key")
	}
}

func TestKuznechik_BlockSize(t *testing.T) {
	c, err := NewKuznechik(make([]byte, KuznechikKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockSize() != KuznechikBlockSize {
		t.Errorf("BlockSize: got %d want %d", c.BlockSize(), KuznechikBlockSize)
	}
}

func TestMagma_BlockSize(t *testing.T) {
	m, err := NewMagma(make([]byte, MagmaKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if m.BlockSize() != MagmaBlockSize {
		t.Errorf("BlockSize: got %d want %d", m.BlockSize(), MagmaBlockSize)
	}
}

func TestKuznechik_Encrypt_PanicShortSrc(t *testing.T) {
	c, _ := NewKuznechik(make([]byte, KuznechikKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short src")
		}
	}()
	c.Encrypt(make([]byte, KuznechikBlockSize), make([]byte, 5))
}

func TestKuznechik_Encrypt_PanicShortDst(t *testing.T) {
	c, _ := NewKuznechik(make([]byte, KuznechikKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short dst")
		}
	}()
	c.Encrypt(make([]byte, 5), make([]byte, KuznechikBlockSize))
}

func TestKuznechik_Decrypt_PanicShortSrc(t *testing.T) {
	c, _ := NewKuznechik(make([]byte, KuznechikKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short src")
		}
	}()
	c.Decrypt(make([]byte, KuznechikBlockSize), make([]byte, 5))
}

func TestKuznechik_Decrypt_PanicShortDst(t *testing.T) {
	c, _ := NewKuznechik(make([]byte, KuznechikKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short dst")
		}
	}()
	c.Decrypt(make([]byte, 5), make([]byte, KuznechikBlockSize))
}

func TestMagma_Encrypt_PanicShortSrc(t *testing.T) {
	c, _ := NewMagma(make([]byte, MagmaKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short src")
		}
	}()
	c.Encrypt(make([]byte, MagmaBlockSize), make([]byte, 3))
}

func TestMagma_Encrypt_PanicShortDst(t *testing.T) {
	c, _ := NewMagma(make([]byte, MagmaKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short dst")
		}
	}()
	c.Encrypt(make([]byte, 3), make([]byte, MagmaBlockSize))
}

func TestMagma_Decrypt_PanicShortSrc(t *testing.T) {
	c, _ := NewMagma(make([]byte, MagmaKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short src")
		}
	}()
	c.Decrypt(make([]byte, MagmaBlockSize), make([]byte, 3))
}

func TestMagma_Decrypt_PanicShortDst(t *testing.T) {
	c, _ := NewMagma(make([]byte, MagmaKeySize))
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short dst")
		}
	}()
	c.Decrypt(make([]byte, 3), make([]byte, MagmaBlockSize))
}
