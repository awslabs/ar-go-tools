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

package sub

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"golang.org/x/exp/rand"
)

type Req struct {
	Ctx   context
	Input interface{}
}

func RandReq() (string, Req) {
	var input interface{}
	var method string
	var content any
	err := json.Unmarshal([]byte("{\"A\": \"B\"}"), content)
	if err != nil {
		panic(err)
	}
	switch rand.Intn(3) {
	case 0:
		method = "A"
		input = content
	case 1:
		method = "B"
		input = content
	case 2:
		method = "C"
		input = content
	}
	return method, Req{
		Ctx: context{
			Dummy: rand.Int() > 0,
		},
		Input: input,
	}
}

type context struct {
	Dummy bool
}

type CallingMachine struct {
	MethodCache map[string]reflect.Value
}

func (c *CallingMachine) populateMethodCache(impl interface{}) error {
	val := reflect.ValueOf(impl)

	valCheck := val
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		valCheck = val.Elem()
	}
	if valCheck.Kind() != reflect.Struct {
		return errors.New("service implementation must be a struct or pointer to struct")
	}

	typ := val.Type()
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		// amazonq-ignore-next-line
		c.MethodCache[name] = val.MethodByName(name)
	}

	return nil
}

// invoke calls the operation by its name
func (c *CallingMachine) Invoke(opName string, r Req) bool {
	inputs := make([]reflect.Value, 1, 2)
	inputs[0] = reflect.ValueOf(r.Ctx)
	if r.Input != nil {
		inputs = append(inputs, reflect.ValueOf(r.Input))
	}
	// Ensure that we have a valid operation to invoke.
	// Comments
	method, ok := c.MethodCache[opName]
	if !ok {
		return false
	}
	// Comments shouldn't break rewrites
	output := method.Call(inputs)
	// Comments
	fmt.Printf("Output: %+v", output)
	return true
}

func Start(impl interface{}) *CallingMachine {
	s := &CallingMachine{
		MethodCache: map[string]reflect.Value{},
	}
	s.populateMethodCache(impl)
	return s
}
