// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package vko implements the VKO key agreement function specified by
// RFC 7836, operating over the elliptic curves of ГОСТ Р 34.10-2012.
//
// VKO derives a shared secret from a local private key and a remote public
// key plus a UKM (user keying material). Both 256-bit and 512-bit curve
// families are supported.
//
// KAT-verified against RFC 7836 Appendix B.
package vko
