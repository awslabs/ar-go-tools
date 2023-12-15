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

// Package capabilities implements a capabilities analysis which uses the capslock analyzer as a backend.
package capabilities

import (
	"go/types"
	"sync"

	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/google/capslock/analyzer"
	"github.com/google/capslock/interesting"
	"github.com/google/capslock/proto"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// DefaultClassifier is the default capabilities classifier.
type DefaultClassifier struct {
	classifier *interesting.Classifier
	capability map[*ssa.Function]proto.Capability
	mu         sync.Mutex
}

// NewDefaultClassifier initializes a DefaultClassifier with pkgs.
func NewDefaultClassifier(pkgs []*packages.Package) *DefaultClassifier {
	queriedPackages := make(map[*types.Package]struct{})
	// query all packages in pkgs
	for _, pkg := range pkgs {
		queriedPackages[pkg.Types] = struct{}{}
	}

	classifier := interesting.DefaultClassifier()
	caps := make(map[*ssa.Function]proto.Capability)
	outputCall := func(from *callgraph.Node, to *callgraph.Node) {} // do nothing
	outputCapability := func(n *callgraph.Node, c proto.Capability) {
		caps[n.Func] = c
	}

	analyzer.CapabilityGraph(pkgs, queriedPackages, classifier, outputCall, outputCapability)

	return &DefaultClassifier{
		classifier: classifier,
		capability: caps,
		mu:         sync.Mutex{},
	}
}

// CanClassify returns true if c can classify f.
// This is true when f's caller's package is "above" the classification "boundary".
// The classification boundary is (for now) defined as the standard library.
// Therefore, if f is called outside the standard library, e.g. in user-defined or library code,
// then f can be classified.
func (c *DefaultClassifier) CanClassify(f *ssa.Function) bool {
	return !summaries.IsStdFunction(f)
}

// ClassifyFunc classifies f in package pkg with a capability.
// Returns proto.Capability_CAPABILITY_UNSPECIFIED if f could not be classified.
func (c *DefaultClassifier) ClassifyFunc(f *ssa.Function, pkg string) proto.Capability {
	if f == nil || c == nil {
		return proto.Capability_CAPABILITY_UNSPECIFIED
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cp, ok := c.capability[f]; ok {
		return cp
	}

	if c.classifier != nil {
		cp := c.classifier.FunctionCategory(pkg, f.Name())
		c.capability[f] = cp
		return cp
	}

	return proto.Capability_CAPABILITY_UNSPECIFIED
}
