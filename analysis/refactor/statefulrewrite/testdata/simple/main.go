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
	"reflect"
)

type MethodGroup struct {
	dummy bool
}

func (m MethodGroup) A() {

}

func (m MethodGroup) B() {

}

func (m MethodGroup) C() {

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

// invoke calls the operation that the request is targeting.
func (c *CallingMachine) invoke(opName string) bool {
	inputs := make([]reflect.Value, 1, 2)

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
	machine.invoke("A")
}
