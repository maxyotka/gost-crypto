// Copyright (C) 2026 maxyotka
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package gost341112_test

import (
	"fmt"

	"github.com/maxyotka/gost-crypto/gost341112"
)

func ExampleNew256() {
	h := gost341112.New256()
	h.Write([]byte("Привет, мир!"))
	fmt.Printf("%x\n", h.Sum(nil))
	// Output: ab77390b10fbb5e03e08a7a1183fc820b3b9c5b583bc77898b1e40aef3e81f6d
}

func ExampleSum256() {
	hash := gost341112.Sum256([]byte("Hello, ГОСТ!"))
	fmt.Printf("%x\n", hash)
	// Output: bf2fd63ccc0d229eae92cb17964b38ecdd4510ac785ac3ceb25180f2cd4001de
}
