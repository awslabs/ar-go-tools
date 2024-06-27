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
)

func TestFmtErrorf() {
	x := source3() // @Source(TestFmtErrorf)
	eTainted := fmt.Errorf("error: %s", x)
	sink2(eTainted) // @Sink(TestFmtErrorf)
	y := genStr()
	eNotTainted := fmt.Errorf("error: %s", y)
	sink2(eNotTainted) //  no false positive because of no-effect-functions include fmt.Errorf
}

func main() {
	TestFmtErrorf()
}
