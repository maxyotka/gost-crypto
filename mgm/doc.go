// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package mgm implements the Multilinear Galois Mode of operation — an
// authenticated encryption scheme (AEAD) specified by RFC 9058.
//
// MGM works with any [crypto/cipher.Block] of 64 or 128 bits; Kuznyechik
// and Magma from [github.com/maxyotka/gost-crypto/gost341215] are the
// intended block ciphers. The returned type implements [crypto/cipher.AEAD].
//
// KAT-verified against the test vectors in RFC 9058 Appendix A.
package mgm
