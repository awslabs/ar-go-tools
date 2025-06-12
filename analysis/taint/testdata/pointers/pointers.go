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

func main() {
	dc := outer{in: &inner{secrets: secrets{}}}
	in := dc.in
	in.setSecret()
	// dc.in = in
	fmt.Println(string(dc.in.secrets.secret)) // @Sink(ex1)
}

type outer struct {
	in *inner
}

type inner struct {
	secrets secrets
}

func (i *inner) setSecret() {
	i.secrets.secret = source() // @Source(ex1)
}

type secrets struct {
	secret []byte
}

func source() []byte {
	return []byte("secret")
}
