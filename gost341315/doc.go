// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341315 implements the block cipher modes of operation defined
// by ГОСТ Р 34.13-2015: ECB, CBC, CFB, CTR, OFB and MAC.
//
// Modes work with any [crypto/cipher.Block], including Kuznyechik and Magma
// from [github.com/maxyotka/gost-crypto/gost341215]. CBC, CFB and OFB
// additionally support the GOST shift-register extension (m > n): pass an
// IV longer than the block size to enable it.
//
// KAT-verified against Appendix A of ГОСТ Р 34.13-2015.
package gost341315
