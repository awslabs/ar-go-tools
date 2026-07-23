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
	"fmt"
	"go/types"
	"strings"
	"time"
	"unicode"

	"github.com/awslabs/ar-go-tools/analysis/taint"
	"golang.org/x/tools/go/ssa"
)

// interestingReasons applies requirements.md's classification rule: a function reached by taint
// propagation (implicit via map membership in InterestingFunctions) is interesting if it shows a
// potential cause of state-space explosion or of taint-analysis-specific unsoundness. It returns
// the specific reason(s) the function was (or wasn't, if empty) classified as interesting, so the
// raw data records *why* each function was flagged instead of just the raw signal values.
func interestingReasons(sig *taint.InterestingFunctionSignals) []string {
	const (
		slowIntraProceduralThreshold = 5 * time.Second
		largeNumValuesThreshold      = 1000
	)
	var reasons []string
	for _, u := range sig.Unsoundness {
		reasons = append(reasons, "unsoundness:"+string(u))
	}
	if sig.IntraTime > slowIntraProceduralThreshold {
		reasons = append(reasons, fmt.Sprintf("slow-intra-procedural:%.2fs", sig.IntraTime.Seconds()))
	}
	if sig.NumValues > largeNumValuesThreshold {
		reasons = append(reasons, fmt.Sprintf("large-num-values:%d", sig.NumValues))
	}
	if sig.IsRecursive {
		reasons = append(reasons, "recursive")
	}
	// recordContextLossFanout already filters out single-destination losses (not meaningful
	// fanout), so any entry here is real.
	for _, loss := range sig.ContextLosses {
		reasons = append(reasons, fmt.Sprintf("context-loss:%s(%d)", loss.Kind, loss.Degree))
	}
	// Multiple call sites can independently dispatch the same (interface, method) with
	// genuinely different NumImpls (see InterfaceFanout.Callsite in interface_fanouts below for
	// the full detail); for a quick-glance reason, only the distinct NumImpls values matter, not
	// every call site.
	seenFanoutReasons := map[string]bool{}
	for _, fanout := range sig.InterfaceFanouts {
		reason := fmt.Sprintf("interface-fanout:%s.%s(%d)", fanout.InterfaceName, fanout.MethodName, fanout.NumImpls)
		if !seenFanoutReasons[reason] {
			seenFanoutReasons[reason] = true
			reasons = append(reasons, reason)
		}
	}
	return reasons
}

// MethodEntry is one entry in the to_summarize.json schema: either a plain function
// ({Package, Function}), a concrete method ({Package, Receiver, Method}), or an interface method
// ({Package, Interface, Method}).
type MethodEntry struct {
	Package   string `json:"package"`
	Function  string `json:"function,omitempty"`
	Receiver  string `json:"receiver,omitempty"`
	Interface string `json:"interface,omitempty"`
	Method    string `json:"method,omitempty"`
}

// classifyEntries decides which to_summarize.json entries f contributes, given its recorded
// signals. If f was reached via one or more public interface dispatches, it contributes one
// entry per distinct (interface, method) pair instead of its own concrete entry: this is exactly
// the aggregation the InterfaceFanouts design enables, and it's valid even if f's own receiver
// type is unexported (a private implementation of a public interface is still addressable via
// the interface). Otherwise, it contributes its own concrete entry, but only if addressable (an
// exported function, or a method with an exported receiver type).
func classifyEntries(f *ssa.Function, sig *taint.InterestingFunctionSignals) []MethodEntry {
	seen := map[MethodEntry]bool{}
	var entries []MethodEntry
	for _, fanout := range sig.InterfaceFanouts {
		if !isPublicInterfaceName(fanout.InterfaceName) {
			continue
		}
		entry := MethodEntry{
			Package:   fanout.InterfacePackage,
			Interface: fanout.InterfaceName,
			Method:    fanout.MethodName,
		}
		if !seen[entry] {
			seen[entry] = true
			entries = append(entries, entry)
		}
	}
	if len(entries) > 0 {
		return entries
	}
	if entry, addressable := methodEntryFor(f); addressable {
		return []MethodEntry{entry}
	}
	return nil
}

// isExportedName returns true if name starts with an uppercase letter (Go's exported-identifier
// rule).
func isExportedName(name string) bool {
	return name != "" && unicode.IsUpper(rune(name[0]))
}

// isPublicInterfaceName returns true if name is an exported, named interface (not an anonymous
// interface literal like "interface{ Temporary() bool }" or an unexported name like "temporary").
func isPublicInterfaceName(name string) bool {
	if strings.HasPrefix(name, "interface{") || strings.HasPrefix(name, "interface {") {
		return false
	}
	return isExportedName(name)
}

// methodEntryFor builds a MethodEntry describing f directly: a plain function, or a concrete
// method with its receiver type. addressable is false if f's own name is unexported (e.g.
// "readFromUntil") or its receiver type is unexported (e.g. "inclusiveRules"): such a function or
// method can't be named in a dataflow-contract entry from outside its package.
func methodEntryFor(f *ssa.Function) (entry MethodEntry, addressable bool) {
	if !isExportedName(f.Name()) {
		return MethodEntry{}, false
	}
	pkgPath := ""
	if f.Package() != nil && f.Package().Pkg != nil {
		pkgPath = f.Package().Pkg.Path()
	}
	recv := f.Signature.Recv()
	if recv == nil {
		return MethodEntry{Package: pkgPath, Function: f.Name()}, true
	}
	named, _ := recv.Type().(*types.Named)
	isPtr := false
	if ptr, ok := recv.Type().(*types.Pointer); ok {
		isPtr = true
		named, _ = ptr.Elem().(*types.Named)
	}
	if named == nil {
		return MethodEntry{}, false
	}
	recvType := named.Obj().Name()
	if isPtr {
		recvType = "*" + recvType
	}
	entry = MethodEntry{Package: pkgPath, Receiver: recvType, Method: f.Name()}
	return entry, named.Obj().Exported()
}
