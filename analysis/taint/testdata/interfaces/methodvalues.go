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

type Container struct {
	value string
}

func (c Container) GetValue() string {

	// Method on value
	return c.value
}

func (c *Container) SetValue(s string) {
	// Method on pointer
	// Bad code practice, but it's for testing
	c.value = s
}

func (c Container) ProcessAndSink() {
	// Method on value
	sink(c.value) // @Sink(methodvalue1)
}

type Processor interface {
	Process() string
}

func (c Container) Process() string {
	return c.value
}

func testMethodValues() {
	tainted := Container{value: source()} // @Source(methodvalue1)
	clean := Container{value: "clean"}

	// Method value from instance
	getValue := tainted.GetValue
	sink(getValue()) // @Sink(methodvalue1)

	// Method value from type
	processFunc := Container.ProcessAndSink
	processFunc(tainted) // should reach sink inside method
	processFunc(clean)   // should not reach sink inside method

	// Method value with interface
	var processor Processor = Container{value: source()} // @Source(methodvalue3)
	processMethod := processor.Process
	// Use method's value and call it, still propagates taint
	sink(processMethod()) // @Sink(methodvalue3)

	// Pointer method value
	container := &Container{}
	setValue := container.SetValue
	// Use method's value to taint the data, still propagates taint
	setValue(source())    // @Source(methodvalue4)
	sink(container.value) // @Sink(methodvalue4)
}
