// Copyright 2020 Google LLC
// Modifications Copyright Amazon.com, Inc. or its affiliates
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

package core

import (
	"fmt"
	"math/rand"
	"strconv"
)

type SourceT string

type Container struct {
	Data string
}

func Source1() string {
	return strconv.Itoa(rand.Int()) + "tainted"
}

func Source() string {
	return strconv.Itoa(rand.Int()) + "tainted"
}

func Source2() SourceT {
	return SourceT(strconv.Itoa(rand.Int()) + "tainted")
}

func Source3() Container {
	return Container{Data: "tainted" + strconv.Itoa(rand.Int())}
}

func Sink(x ...any) {
	fmt.Println(x)
}

func Innocuous() string {
	return "ok"
}
