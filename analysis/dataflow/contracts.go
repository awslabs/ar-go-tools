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

package dataflow

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"golang.org/x/tools/go/ssa"
)

// A Contract is an object that specifies the dataflow some specific function should satisfy.
//
// If interfaceId is not empty, then it is an interface contract:
// the interface id is the long name of the interface, i.e. package name followed by the type name, and a map from
// method names to dataflow summaries. All implementations of the specified methods must satisfy the contract.
//
// If the objectPath is not empty, then it is a function contract:
// the objectPath specifies the long name of the object, either package name followed by struct name, or package
// name only. The methods are the dataflow summaries of the methods in question.
//
// objectPath and interfaceId should not be both specified.
type Contract struct {
	InterfaceID string
	ObjectPath  string
	Methods     map[string]summaries.Summary
}

// Key returns a string identifying the method or function in the given contract.
// This can be used to store method information consistently across different usages
func (c Contract) Key(method string) string {
	if c.InterfaceID != "" {
		return c.InterfaceID + "." + method
	} else if c.ObjectPath != "" {
		return c.ObjectPath + "." + method
	} else {
		return method
	}
}

// InterfaceMethodKey returns the contract method key of a call instruction if it can be resolved
func InterfaceMethodKey(callsite ssa.CallInstruction) (bool, string) {
	if callsite == nil || callsite.Common() == nil {
		return false, ""
	}
	if !callsite.Common().IsInvoke() {
		return false, ""
	}

	methodFunc := callsite.Common().Method
	methodKey := callsite.Common().Value.Type().String() + "." + methodFunc.Name()
	return true, methodKey
}

// LoadDefinitions loads the dataflow definitions contained in the json file at filename
// returns an error if it could not read the file, or the file is not well formatted.
func LoadDefinitions(fileName string) ([]Contract, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var data []Contract
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}
	for _, contract := range data {
		// only one of InterfaceID and DataflowEdge should be given
		if contract.InterfaceID == "" && contract.ObjectPath == "" {
			return data, fmt.Errorf("InterfaceID and DataflowEdge should not be both empty")
		}
		if contract.InterfaceID != "" && contract.ObjectPath != "" {
			return data, fmt.Errorf("InterfaceID and DataflowEdge should not be both specified")
		}
	}

	return data, nil
}
