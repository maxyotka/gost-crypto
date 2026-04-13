// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341215 implements the Kuznyechik (128-bit) and Magma (64-bit)
// block ciphers defined by ГОСТ Р 34.12-2015.
//
// Both ciphers implement [crypto/cipher.Block]. Kuznyechik uses precomputed
// S+L tables for performance; all operations are zero-allocation on the
// hot path. Key material is zeroed on cipher destruction.
//
// KAT-verified against RFC 7801 (Kuznyechik) and RFC 8891 (Magma).
//
//	block, err := gost341215.NewKuznechik(key) // or NewMagma(key)
//	block.Encrypt(dst, src)
//
// Use [github.com/maxyotka/gost-crypto/gost341315] for modes of operation
// (ECB, CBC, CFB, CTR, OFB, MAC).
package gost341215
