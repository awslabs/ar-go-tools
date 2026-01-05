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
	"sync/atomic"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"golang.org/x/tools/go/ssa"
)

// SsaInfo is holds all the information from a built ssa program with main packages
type SsaInfo struct {
	Prog     *ssa.Program
	Packages []*ssa.Package
	Mains    []*ssa.Package
}

// This global variable should only be read and modified through GetUniqueFunctionID
var uniqueFunctionIDCounter uint32 = 0

// GetUniqueFunctionID increments and returns the Value of the global used to give unique function ids.
func GetUniqueFunctionID() uint32 {
	x := atomic.AddUint32(&uniqueFunctionIDCounter, 1)
	return x
}

// ComputeMethodImplementations populates a map from method implementation type string to the different implementations
// corresponding to that method.
// The map can be indexed by using the signature of an interface method and calling String() on it.
// If the provided contracts map is non-nil, then the function also builds a summary graph for each interface
// method such that contracts[methodId] = nil
func ComputeMethodImplementations(p *ssa.Program, implementations map[string]map[*ssa.Function]bool,
	contracts map[string]*SummaryGraph, keys map[string]string) error {
	err := lang.ComputeMethodImplementations(p, implementations, keys)
	if err != nil {
		return err
	}

	for key, implementationSet := range implementations {
		for implementation := range implementationSet {
			addContractSummaryGraph(contracts, key, implementation, GetUniqueFunctionID())
		}
	}
	return nil
}

// addContractSummaryGraph sets the Value of contract[methodId] to a new summary of function if the methodId key
// is present in contracts but the associated Value is nil
// Does nothing if contracts is nil.
func addContractSummaryGraph(contracts map[string]*SummaryGraph, methodID string, function *ssa.Function, id uint32) {
	if contracts == nil || function == nil {
		return
	}
	// Entry must be present
	if curSummary, ok := contracts[methodID]; ok {
		if curSummary == nil {
			contracts[methodID] = NewSummaryGraph(nil, function, id, nil, nil)
		}
	}
}
