// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	// "crypto/elliptic"
	"fmt"
	"math/big"
	"regexp"
)

func main() {
	// Test regexp.Compile - complex NFA/DFA construction
	re, err := regexp.Compile(source1())
	if err != nil {
		fmt.Printf("Regexp error: %v\n", err)
	} else {
		fmt.Printf("Regexp compiled: %v\n", re.String())
	}

	// // Test math/big.Int.Exp - modular exponentiation with very complex algorithm
	// base := source2()
	// exp := big.NewInt(67890)
	// mod := big.NewInt(98765)
	// result := new(big.Int)
	// result.Exp(base, exp, mod)
	// fmt.Printf("Modular exponentiation result: %v\n", result.String())

	// // Test crypto/elliptic ScalarMult - elliptic curve point multiplication
	// curve := elliptic.P256()
	// x, _ := new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	// y, _ := new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	// scalar := source3()

	// rx, ry := curve.ScalarMult(x, y, scalar)
	// fmt.Printf("Elliptic curve result: x=%v, y=%v\n", rx.String()[:20]+"...", ry.String()[:20]+"...")
}

func source1() string {
	return `^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`
}

func source2() *big.Int {
	return big.NewInt(12345)
}

func source3() []byte {
	return []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
}
