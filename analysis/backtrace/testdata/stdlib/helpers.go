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
	"math/rand"
	"strconv"
)

type T struct {
	Data  string
	Other string
}

type R string

func genStr() string {
	return strconv.Itoa(rand.Int()) + "1234"
}

func genT() T {
	return T{
		Data:  genStr(),
		Other: genStr() + "ok",
	}
}

func source1() T {
	return T{
		Data:  strconv.Itoa(rand.Int()) + "tainted",
		Other: "ok",
	}
}

func source2() R {
	return R(strconv.Itoa(rand.Int()) + "tainted")
}

func sink2(_ ...any) {}

func sink1(s string) {
	fmt.Printf("Sink: %s\n", s)
}
