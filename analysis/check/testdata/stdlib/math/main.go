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
	"fmt"
	"math/big"
)

func main() {
	// Test math/big.Int.Exp - modular exponentiation with complex algorithm
	base := source()
	exp := big.NewInt(67890)
	mod := big.NewInt(98765)
	result := new(big.Int)
	result.Exp(base, exp, mod)
	fmt.Printf("Modular exponentiation result: %v\n", result.String())
}

func source() *big.Int {
	return big.NewInt(12345)
}
