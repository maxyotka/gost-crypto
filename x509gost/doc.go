// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package x509gost provides interoperability between ГОСТ Р 34.10-2012 keys
// and the standard [crypto/x509] encoding conventions.
//
// It exposes helpers for marshaling and parsing GOST public and private keys
// in PKIX / PKCS#8 form, using the ASN.1 OIDs registered for the 256-bit and
// 512-bit curve families.
package x509gost
