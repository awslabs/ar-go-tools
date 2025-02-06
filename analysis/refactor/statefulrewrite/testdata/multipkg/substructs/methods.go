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

package substructs

import (
	"strconv"
)

type InputA struct {
	ID      int
	Content string
}

type InputB struct {
	ID      int
	Content string
	Origin  string
}

type InputC struct {
	ID      int
	Content string
	Target  string
}

type OutputA struct {
	Response string
}

type OutputB struct {
	Response string
}

type OutputC struct {
	Response string
}

type MethodGroup struct {
	dummy bool
}

func (m MethodGroup) A(a InputA) (OutputA, OutputA) {
	return OutputA{
			Response: "A-" + strconv.Itoa(a.ID),
		}, OutputA{
			Response: "A-" + strconv.Itoa(a.ID),
		}
}

func (m MethodGroup) B(b InputB) OutputB {
	return OutputB{
		Response: "B-" + strconv.Itoa(b.ID) + b.Content,
	}
}

func (m MethodGroup) C(c InputC) (OutputC, error) {
	return OutputC{
		Response: "C-" + strconv.Itoa(c.ID) + c.Target,
	}, nil
}
