// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341112

import "encoding/asn1"

// Hash function OIDs (TC-26).
var (
	// OIDHash256 is the OID for Stribog-256.
	OIDHash256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// OIDHash512 is the OID for Stribog-512.
	OIDHash512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

// HMAC OIDs (TC-26).
var (
	// OIDHMAC256 is the OID for HMAC-Stribog-256.
	OIDHMAC256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 1}
	// OIDHMAC512 is the OID for HMAC-Stribog-512.
	OIDHMAC512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 2}
)
