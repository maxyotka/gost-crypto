// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341012

import "encoding/asn1"

// GOST R 34.10-2012 algorithm OIDs (TC-26).
var (
	// OIDSignature256 is the OID for GOST R 34.10-2012 with 256-bit key.
	OIDSignature256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// OIDSignature512 is the OID for GOST R 34.10-2012 with 512-bit key.
	OIDSignature512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
)

// Curve parameter set OIDs.
var (
	// 256-bit curves
	OIDCurve256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	OIDCurve256B = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1} // CryptoPro-A
	OIDCurve256C = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2} // CryptoPro-B
	OIDCurve256D = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3} // CryptoPro-C

	// 512-bit curves
	OIDCurve512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	OIDCurve512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	OIDCurve512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
)

// CurveByOID returns the curve for the given OID, or nil if unknown.
func CurveByOID(oid asn1.ObjectIdentifier) *Curve {
	switch {
	case oid.Equal(OIDCurve256A):
		return CurveParamSetA()
	case oid.Equal(OIDCurve256B):
		return CurveParamSetB()
	case oid.Equal(OIDCurve256C):
		return CurveParamSetC()
	case oid.Equal(OIDCurve256D):
		return CurveParamSetD()
	case oid.Equal(OIDCurve512A):
		return Curve512ParamSetA()
	case oid.Equal(OIDCurve512B):
		return Curve512ParamSetB()
	case oid.Equal(OIDCurve512C):
		return Curve512ParamSetC()
	default:
		return nil
	}
}

// OIDForCurve returns the OID for the given curve based on its parameters.
// Returns nil if the curve is not a known parameter set.
func OIDForCurve(c *Curve) asn1.ObjectIdentifier {
	if c == nil {
		return nil
	}
	// Compare by field prime P and base point X (sufficient to identify).
	known := []struct {
		curve *Curve
		oid   asn1.ObjectIdentifier
	}{
		{CurveParamSetA(), OIDCurve256A},
		{CurveParamSetB(), OIDCurve256B},
		{CurveParamSetC(), OIDCurve256C},
		{CurveParamSetD(), OIDCurve256D},
		{Curve512ParamSetA(), OIDCurve512A},
		{Curve512ParamSetB(), OIDCurve512B},
		{Curve512ParamSetC(), OIDCurve512C},
	}
	for _, k := range known {
		if c.P.Cmp(k.curve.P) == 0 && c.X.Cmp(k.curve.X) == 0 {
			return k.oid
		}
	}
	return nil
}
