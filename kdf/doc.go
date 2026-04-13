// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package kdf implements key-derivation and key-protection primitives on top
// of the GOST hash and block-cipher families:
//
//   - HMAC over Streebog (RFC 7836)
//   - CMAC over Kuznyechik and Magma
//   - KDF_GOSTR3411_2012_256 (R 50.1.113-2016)
//   - PBKDF2 over HMAC-Streebog (R 50.1.111-2016)
//   - Key wrap constructions
//
// All primitives are KAT-verified against the corresponding recommendations.
package kdf
