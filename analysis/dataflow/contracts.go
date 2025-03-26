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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"golang.org/x/tools/go/ssa"
)

// rawContract is the type of contracts for serialization/deserialization that gets compiled
// into either an interface or a function contract
type rawContract struct {
	InterfaceID string
	ObjectPath  string
	Methods     map[string]summaries.Summary
}

// Compile checks the raw contract is either an interface of concrete object contract and then
// returns a Contract interface.
func (c rawContract) Compile() (Contract, error) {
	if c.InterfaceID != "" && c.ObjectPath != "" {
		return nil, fmt.Errorf("contract cannot specify both interface and object path")
	}

	if c.InterfaceID == "" && c.ObjectPath == "" {
		return nil, fmt.Errorf("contract must specify either interface or object path")
	}
	methods := funcutil.MapValues(c.Methods, func(s summaries.Summary) summaries.Summarizer {
		return s
	})
	// if the interface id is set, then this is an interface contract
	if c.InterfaceID != "" {
		return IfaceContract{
			InterfaceID: c.InterfaceID,
			methods:     methods,
		}, nil
	}
	return FnContract{
		ObjectPath: c.ObjectPath,
		methods:    methods,
	}, nil
}

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
type Contract interface {
	// Key returns a string identifying the method or function in the given contract.
	// This can be used to store method information consistently across different usages
	Key(method string) string
	Methods() map[string]summaries.Summarizer
	IsInterface() bool
}

// IfaceContract is a contract for an interface: it applies to each implmentation of the
// interface's methods
type IfaceContract struct {
	InterfaceID string
	methods     map[string]summaries.Summarizer
}

// Methods returns the dataflow summaries for the methods in the contract
func (c IfaceContract) Methods() map[string]summaries.Summarizer {
	return c.methods
}

// Key returns a string that matches interface method ids
func (c IfaceContract) Key(method string) string {
	return c.InterfaceID + "." + method
}

// IsInterface returns true
func (c IfaceContract) IsInterface() bool {
	return true
}

// FnContract is a function contract, it applies only to that set of function implementations
type FnContract struct {
	ObjectPath string
	methods    map[string]summaries.Summarizer
}

// Key returns the string identifying the function string
func (c FnContract) Key(method string) string {
	if c.ObjectPath == "" {
		return method
	}
	return c.ObjectPath + "." + method
}

// Methods returns the dataflow summaries for the methods in the contract
func (c FnContract) Methods() map[string]summaries.Summarizer {
	return c.methods
}

// IsInterface returns false
func (c FnContract) IsInterface() bool {
	return false
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
	data, err := loadRawIndexedFormat(fileName)
	if err == nil {
		// Loaded successfully using the legacy (with indices) format; return
		return data, nil
	}
	// Try loading using the new (string-based) format
	return loadSummariesFrontendFormat(fileName)
}

func loadSummariesFrontendFormat(fileName string) ([]Contract, error) {
	frontendSummaries, err := summaries.ParseSummariesFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not parse and validate summaries file: %w", err)
	}
	contracts := make([]Contract, 0, len(frontendSummaries))
	// Convert to the new format
	for _, frontendSummary := range frontendSummaries {
		switch s := frontendSummary.(type) {
		case summaries.IfaceMethodFlowSummary:
			contract := IfaceContract{
				InterfaceID: packageAndInterfaceToID(s.Package(), s.Interface),
				methods: map[string]summaries.Summarizer{
					s.Method: s.Summary(),
				},
			}
			contracts = append(contracts, contract)
		case summaries.FunctionFlowSummary:
			contract := FnContract{
				ObjectPath: s.Package(),
				methods: map[string]summaries.Summarizer{
					s.Function: s.Summary(),
				},
			}
			contracts = append(contracts, contract)
		case summaries.ReceiverMethodFlowSummary:
			contract := FnContract{
				ObjectPath: packageAndReceiverToID(s.Package(), s.Receiver),
				methods: map[string]summaries.Summarizer{
					s.Method: s.Summary(),
				},
			}
			contracts = append(contracts, contract)
		default:
			continue
		}
	}
	return contracts, nil
}

func packageAndInterfaceToID(packageName, interfaceName string) string {
	return packageName + "." + interfaceName
}

func packageAndReceiverToID(packageName, receiverName string) string {
	// The function is a regular function, no receiver
	if receiverName == "" {
		return packageName
	}
	// The receiver is a pointer to a type, the string looks like (*package.receiver)
	if actualI, isPtr := strings.CutPrefix(receiverName, "*"); isPtr {
		return "(*" + packageName + "." + actualI + ")"
	}
	// The receiver is not a pointer, the string looks like (package.receiver)
	return "(" + packageName + "." + receiverName + ")"
}

func loadRawIndexedFormat(fileName string) ([]Contract, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var data []rawContract
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}
	var res []Contract
	var errs error
	for _, rawC := range data {
		// only one of InterfaceID and DataflowEdge should be given
		contract, err := rawC.Compile()
		errs = errors.Join(errs, err) // try all the contracts
		res = append(res, contract)
	}

	return res, errs
}
