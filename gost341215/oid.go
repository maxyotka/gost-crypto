// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341215

import "encoding/asn1"

// Block cipher OIDs (TC-26).
var (
	// OIDKuznechik is the OID for the Kuznechik block cipher.
	OIDKuznechik = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 2}
	// OIDMagma is the OID for the Magma block cipher.
	OIDMagma = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 1}
)
