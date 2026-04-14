// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package x509gost_test

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/maxyotka/gost-crypto/gost341012"
	"github.com/maxyotka/gost-crypto/x509gost"
)

// ExampleCreateSelfSigned creates a self-signed X.509 certificate with a
// GOST R 34.10-2012 key pair using the 256-bit curve paramSetA.
func ExampleCreateSelfSigned() {
	curve := gost341012.CurveParamSetA()

	priv, pub, err := gost341012.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	subject := pkix.Name{
		CommonName:   "example.test",
		Organization: []string{"gost-crypto"},
	}

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(1, 0, 0)

	der, err := x509gost.CreateSelfSigned(priv, pub, subject, notBefore, notAfter)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(der) > 0)
	// Output: true
}
