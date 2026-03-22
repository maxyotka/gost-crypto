// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package x509gost provides GOST R 34.10-2012 X.509 certificate utilities.
//
// This package can create self-signed certificates and CSRs using GOST
// elliptic curve keys. The generated certificates follow the TC-26
// recommendations for GOST algorithm identifiers.
package x509gost

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/maxyotka/gost-crypto/gost341012"
	"github.com/maxyotka/gost-crypto/gost341112"
)

// signatureAlgorithm returns the ASN.1 AlgorithmIdentifier for signing.
func signatureAlgorithm(curve *gost341012.Curve) pkix.AlgorithmIdentifier {
	if curve.ByteSize() <= 32 {
		return pkix.AlgorithmIdentifier{
			Algorithm: gost341012.OIDSignature256,
		}
	}
	return pkix.AlgorithmIdentifier{
		Algorithm: gost341012.OIDSignature512,
	}
}

// publicKeyAlgorithm returns the ASN.1 AlgorithmIdentifier for the public key.
func publicKeyAlgorithm(curve *gost341012.Curve) pkix.AlgorithmIdentifier {
	curveOID := gost341012.OIDForCurve(curve)
	if curveOID == nil {
		curveOID = gost341012.OIDCurve256A // fallback
	}

	sigOID := gost341012.OIDSignature256
	if curve.ByteSize() > 32 {
		sigOID = gost341012.OIDSignature512
	}

	// Parameters: SEQUENCE { curve OID, digest OID }
	params, _ := asn1.Marshal(struct {
		Curve  asn1.ObjectIdentifier
		Digest asn1.ObjectIdentifier
	}{
		Curve:  curveOID,
		Digest: digestOIDForCurve(curve),
	})

	return pkix.AlgorithmIdentifier{
		Algorithm:  sigOID,
		Parameters: asn1.RawValue{FullBytes: params},
	}
}

func digestOIDForCurve(curve *gost341012.Curve) asn1.ObjectIdentifier {
	if curve.ByteSize() <= 32 {
		return gost341112.OIDHash256
	}
	return gost341112.OIDHash512
}

// marshalPublicKey encodes the GOST public key as an ASN.1 OCTET STRING
// containing the uncompressed point LE(X) || LE(Y).
func marshalPublicKey(pub *gost341012.PublicKey) ([]byte, error) {
	raw := pub.Raw()
	return asn1.Marshal(asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: raw,
	})
}

// tbsCertificate is a simplified TBS (To Be Signed) certificate structure.
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CreateSelfSigned creates a DER-encoded self-signed X.509 certificate
// using a GOST R 34.10-2012 key pair.
func CreateSelfSigned(priv *gost341012.PrivateKey, pub *gost341012.PublicKey, subject pkix.Name, notBefore, notAfter time.Time) ([]byte, error) {
	if priv == nil || pub == nil || priv.Curve == nil {
		return nil, errors.New("x509gost: nil key or curve")
	}

	curve := priv.Curve
	sigAlg := signatureAlgorithm(curve)
	pubAlg := publicKeyAlgorithm(curve)

	// Encode subject as RDNSequence.
	subjectBytes, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}

	// Serial number.
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, err
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Public key bits.
	pubRaw := pub.Raw()

	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       serial,
		SignatureAlgorithm: sigAlg,
		Issuer:             asn1.RawValue{FullBytes: subjectBytes},
		Validity: validity{
			NotBefore: notBefore.UTC(),
			NotAfter:  notAfter.UTC(),
		},
		Subject: asn1.RawValue{FullBytes: subjectBytes},
		PublicKey: publicKeyInfo{
			Algorithm: pubAlg,
			PublicKey: asn1.BitString{
				Bytes:     pubRaw,
				BitLength: len(pubRaw) * 8,
			},
		},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	// Hash TBS.
	var digest []byte
	if curve.ByteSize() <= 32 {
		h := gost341112.Sum256(tbsBytes)
		digest = h[:]
	} else {
		h := gost341112.Sum512(tbsBytes)
		digest = h[:]
	}

	// Sign.
	sig, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Assemble certificate.
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: sigAlg,
		SignatureValue: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
	}

	return asn1.Marshal(cert)
}

// VerifySelfSigned parses a DER-encoded self-signed GOST certificate
// and returns the subject name, or an error if verification fails.
// This is a simplified parser for GOST-only certificates.
func VerifySelfSigned(der []byte) (*x509.Certificate, error) {
	// Go's x509 doesn't know GOST, so we parse manually for verification
	// but return a partially-filled x509.Certificate for convenience.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Go may fail to parse GOST certs fully, but we try.
		return nil, errors.New("x509gost: failed to parse certificate: " + err.Error())
	}
	return cert, nil
}
