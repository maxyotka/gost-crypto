// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341112 implements the Streebog hash function (ГОСТ Р 34.11-2012).
//
// Two output sizes are supported: 256 and 512 bits. Both implement [hash.Hash]
// and can be used as drop-in replacements for standard library hashes.
//
// KAT-verified against RFC 6986 and the test vectors in Appendix A of the
// standard.
//
//	h := gost341112.New256()
//	h.Write([]byte("message"))
//	digest := h.Sum(nil)
package gost341112
