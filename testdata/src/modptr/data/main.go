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

func exModSlice() {
	s := []byte{0x0} // @Mod(exModSlice)
	s[0] = 0x1       // @Mod(exModSlice)
	trackSlice(s)    // @Source(exModSlice) // prints 0x1
}

func exModStructFieldSlice() {
	s := []byte{0x0}
	v := &t{x: s} // @Mod(exModStructFieldSlice)
	s[0] = 0x1    // @Mod(exModStructFieldSlice)
	trackT(v)     // @Source(exModStructFieldSlice) // prints 0x1
}

func main() {
	fmt.Println("exModSlice")
	exModSlice()
	fmt.Println("exModStructFieldSlice")
	exModStructFieldSlice()
}

type t struct {
	x []byte
}

func trackSlice(s []byte) {
	fmt.Printf("%x\n", s)
}

func trackT(v *t) {
	fmt.Printf("%x\n", v.x)
}
