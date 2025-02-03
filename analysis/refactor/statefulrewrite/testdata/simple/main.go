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
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
)

type context struct {
	Dummy bool
}

type Req struct {
	Ctx   context
	Input interface{}
}

func randReq() (string, Req) {
	var input interface{}
	var method string
	switch rand.Intn(3) {
	case 0:
		method = "A"
		input = InputA{
			ID:      rand.Int(),
			Content: "A",
		}
	case 1:
		method = "B"
		input = InputB{
			ID:      rand.Int(),
			Content: "B",
			Origin:  "origin-" + strconv.Itoa(rand.Intn(10)),
		}
	case 2:
		method = "C"
		input = InputC{
			ID:      rand.Int(),
			Content: "C",
			Target:  "target-" + strconv.Itoa(rand.Intn(10)),
		}
	}
	return method, Req{
		Ctx: context{
			Dummy: rand.Int() > 0,
		},
		Input: input,
	}
}

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
		c.MethodCache[name] = val.MethodByName(name)
	}

	return nil
}

// invoke calls the operation by its name
func (c *CallingMachine) invoke(opName string, r Req) bool {
	inputs := make([]reflect.Value, 1, 2)
	inputs[0] = reflect.ValueOf(r.Ctx)
	if r.Input != nil {
		inputs = append(inputs, reflect.ValueOf(r.Input))
	}
	// Ensure that we have a valid operation to invoke.
	method, ok := c.MethodCache[opName]
	if !ok {
		return false
	}
	output := method.Call(inputs)
	fmt.Printf("Output: %+v", output)
	return true
}

func start(impl interface{}) *CallingMachine {
	s := &CallingMachine{
		MethodCache: map[string]reflect.Value{},
	}
	s.populateMethodCache(impl)
	return s
}

func main() {
	methoder := MethodGroup{}
	machine := start(methoder)
	for i := 0; i < 10; i++ {
		m, r := randReq()
		machine.invoke(m, r)
	}
}
