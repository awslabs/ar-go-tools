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

type someInterface interface {
	doA() int
	doB() int
}

type type1 struct {
}

func (object *type1) doA() int {
	return 1
}

func (object *type1) doB() int {
	return 1
}

func doInvoke(instance someInterface) {
	go instance.doA()
	go instance.doB()
}

func main() {
	doInvoke(&type1{})
}
