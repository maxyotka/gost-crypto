// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package gost341012 implements the digital signature algorithm defined by
// ГОСТ Р 34.10-2012 over elliptic curves.
//
// Seven standard curves are supported: four 256-bit parameter sets (paramSetA,
// CryptoPro-A/B/C) and three 512-bit parameter sets (paramSetA/B/C). Private
// keys implement [crypto.Signer] for interoperability with standard Go
// cryptographic plumbing.
//
// Signatures are deterministic in form but generated with a random nonce
// drawn from [crypto/rand]. KAT-verified against RFC 7091 and Appendix A
// of the standard.
package gost341012
