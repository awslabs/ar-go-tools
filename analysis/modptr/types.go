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

package modptr

import (
	"fmt"
	"go/types"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/ssa"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

// typeCache represents a "global" cache for type information.
type typeCache struct {
	// progTypes is all the runtime types in the program.
	progTypes []types.Type
	// implements is a mapping from an interface to all the types that implement
	// the interface.
	implements map[*types.Interface][]types.Type
	// basic is a mapping from a type to all the basic types that it contains.
	basic map[types.Type][]*types.Basic
}

// canTypeAlias returns true if v can be an alias of types ttypes.
//
// v's type can be an alias of t (a type in ttypes) if:
// - the types are the same
// - v's type is a struct and any of v's fields can alias t
// - t's type is a struct and any of t's fields can alias v
func (tc *typeCache) canTypeAlias(ttypes []*types.Basic, v types.Type) bool {
	if tc == nil {
		return true
	}

	vtypes := tc.allBasicTypes(v)
	for _, tt := range ttypes {
		for _, vt := range vtypes {
			if types.AssignableTo(tt, vt) {
				return true
			}
		}
	}

	return false
}

// allBasicTypes returns all the basic types that t contains.
//
// TODO does not yet handle generics
// (but is still sound because it panics on unhandled types)
//
//gocyclo:ignore
func (tc *typeCache) allBasicTypes(t types.Type) []*types.Basic {
	if res, ok := tc.basic[t]; ok {
		return res
	}

	// BFS should be faster because structs tend to have many fields
	// but few of those fields themselves will be structs
	queue := []types.Type{t}
	seen := make(map[types.Type]struct{})
	var res []*types.Basic
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == nil {
			continue
		}
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		switch typ := cur.(type) {
		case *types.Basic:
			// we assume that unsafe is not used to modify or create aliases
			if typ.String() == "unsafe.Pointer" {
				continue
			}

			res = append(res, typ)
		case *types.Signature:
			params := typ.Params()
			queue = append(queue, params)
			recv := typ.Recv()
			if recv != nil {
				queue = append(queue, recv.Type())
			}
		case *types.Tuple:
			for i := 0; i < typ.Len(); i++ {
				et := typ.At(i).Type()
				queue = append(queue, et)
			}
		case *types.Array:
			et := typ.Elem()
			queue = append(queue, et)
		case *types.Slice:
			et := typ.Elem()
			queue = append(queue, et)
		case *types.Chan:
			et := typ.Elem()
			queue = append(queue, et)
		case *types.Map:
			et := typ.Elem()
			queue = append(queue, et)
			kt := typ.Key()
			queue = append(queue, kt)
		case *types.Named:
			ut := typ.Underlying()
			queue = append(queue, ut)
		case *types.Interface:
			ts := tc.interfaceTypes(typ)
			queue = append(queue, ts...)
		case *types.Pointer:
			et := typ.Elem()
			queue = append(queue, et)
		case *types.Struct:
			for i := 0; i < typ.NumFields(); i++ {
				ft := typ.Field(i).Type()
				queue = append(queue, ft)
			}
		default:
			panic(fmt.Errorf("unhandled type: %T", typ))
		}
	}

	tc.basic[t] = res

	return res
}

// interfaceTypes returns all the types in progTypes that implement the
// interface, if it is not pure.
func (tc *typeCache) interfaceTypes(in *types.Interface) []types.Type {
	if res, ok := tc.implements[in]; ok {
		return res
	}

	var res []types.Type
	for _, rt := range tc.progTypes {
		t := rt.Underlying()
		if isSafeType(t) {
			continue
		}
		// if strings.Contains(t.String(), "mock") {
		// 	// skip mock types, which should not be reachable at runtime
		// 	panic(fmt.Errorf("mock type should be unreachable: %v", t.String()))
		// }

		if types.Implements(t, in) {
			res = append(res, t)
		}
	}
	tc.implements[in] = res

	return res
}

func isSafeType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		// remove * prefix for pointer types
		t = ptr.Elem()
	}

	// fast path avoiding string comparisons
	tpkg := typePackage(t)
	if tpkg != nil {
		if _, ok := purePackages[tpkg.Path()]; ok {
			return true
		}
	}

	for name := range purePackages {
		if strings.HasPrefix(t.String(), name) {
			return true
		}
	}
	// if _, ok := purePackages[t.String()]; ok {
	// 	return true
	// }

	// fmt.Printf("unsafe type: %v\n", t)
	return false
}

// typePackage finds the type.Package for a type.
//
// Implementation modified from lang.GetPackageOfType
func typePackage(tp types.Type) *types.Package {
	if ptr, ok := tp.(*types.Pointer); ok {
		tp = ptr.Elem()
	} else if s, ok := tp.(*types.Struct); ok && s.NumFields() == 1 {
		tp = s.Field(0).Type()
	}

	if obj, ok := tp.(interface{ Pkg() *types.Package }); ok {
		return obj.Pkg()
	} else if named, ok := tp.(*types.Named); ok {
		return named.Obj().Pkg()
	}

	return nil
}

func allWriteInstrs(fns map[*ssa.Function]bool) map[ssa.Instruction]struct{} {
	res := make(map[ssa.Instruction]struct{})
	for fn := range fns {
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil {
				return
			}

			switch instr.(type) {
			case *ssa.Alloc, *ssa.Store, *ssa.MapUpdate, *ssa.Send:
				res[instr] = struct{}{}
			}
		})
	}

	return res
}

func allValues(tc *typeCache, ttypes []*types.Basic, fns map[*ssa.Function]bool) map[ssa.Value]struct{} {
	res := make(map[ssa.Value]struct{})
	for fn := range fns {
		if fn == nil {
			continue
		}

		addValuesOfFn(tc, ttypes, fn, res)
	}

	return res
}

func addValuesOfFn(tc *typeCache, ttypes []*types.Basic, fn *ssa.Function, vals map[ssa.Value]struct{}) {
	lang.IterateValues(fn, func(_ int, val ssa.Value) {
		if _, ok := val.(*ssa.Range); ok {
			// Range really isn't a value
			// Panics on *ssa.opaqueType: see https://github.com/golang/go/issues/19670
			return
		}

		if val == nil || val.Parent() == nil || val.Type() == nil {
			return
		}

		// only include values that can alias an entrypoint type
		if !tc.canTypeAlias(ttypes, val.Type()) {
			return
		}

		vals[val] = struct{}{}
	})
}

// isFnPure returns true if no instruction in the body of function f can modify an
// outside value, or the function does not return a pointer.
//
// Assumptions:
// - the analysis is not tracking modifications to a global value
// - Error() methods do not modify external state
func isFnPure(tc *typeCache, valTypes []*types.Basic, f *ssa.Function) bool {
	if _, ok := pureFunctions[f.String()]; ok {
		return true
	}
	if _, ok := purePackages[lang.PackageNameFromFunction(f)]; ok {
		return true
	}

	for _, param := range f.Params {
		if pointer.CanPoint(param.Type()) && tc.canTypeAlias(valTypes, param.Type()) {
			return false
		}
	}

	for _, fv := range f.FreeVars {
		if pointer.CanPoint(fv.Type()) && tc.canTypeAlias(valTypes, fv.Type()) {
			return false
		}
	}

	results := f.Signature.Results()
	for i := 0; i < results.Len(); i++ {
		ret := results.At(i)
		// errors are interface types which are pointers, but they are
		// idiomatically used as values
		if (pointer.CanPoint(ret.Type()) && tc.canTypeAlias(valTypes, ret.Type())) && !lang.IsErrorType(ret.Type()) {
			return false
		}
	}

	return true
}

// pureFunctions represents all the functions that cannot modify external aliases.
//
// This assumes that the arguments' String(), Error(), etc. methods are also
// pure, which is the same assumption that the dataflow analysis makes.
var pureFunctions = map[string]struct{}{
	"print":       {},
	"println":     {},
	"fmt.Print":   {},
	"fmt.Printf":  {},
	"fmt.Println": {},
	"fmt.Errorf":  {},
}

// purePackages represents all the packages that do not contain any functions
// that modify external aliases. Assumptions are the same as pureFunctions.
var purePackages = map[string]struct{}{
	// stdlib
	// "crypto/internal/edwards25519": {},
	// "crypto/internal/nistec":       {},
	// "crypto/internal/nistec/fiat":  {},
	"errors":   {},
	"fmt":      {},
	"internal": {},
	"math/big": {},
	"reflect":  {}, // we assume that reflection is not used to modify aliases
	"regexp":   {},
	"runtime":  {},
	"strconv":  {},
	"strings":  {},
	"sync":     {},
	"syscall":  {},
	"time":     {},
	"unsafe":   {}, // we assume that unsafe is not used to modify aliases
	// dependencies
	"github.com/cihub/seelog":          {},
	"github.com/stretchr/testify/mock": {},
	"github.com/jmespath/go-jmespath":  {},
	"gopkg.in/yaml.v2":                 {},
	"github.com/davecgh/go-spew/spew":  {},
	// agent code
	"github.com/aws/amazon-ssm-agent/common/identity/mocks":         {},
	"github.com/aws/amazon-ssm-agent/agent/plugins/dockercontainer": {},
}

type expensiveFn struct {
	fn      *ssa.Function
	numVals int
}

func mostExpensiveFns(tc *typeCache, ttypes []*types.Basic, fns map[*ssa.Function]bool) []expensiveFn {
	const threshold = 100

	var res []expensiveFn
	for fn := range fns {
		vals := make(map[ssa.Value]struct{})
		addValuesOfFn(tc, ttypes, fn, vals)
		numVals := len(vals)
		if numVals > threshold {
			res = append(res, expensiveFn{fn: fn, numVals: numVals})
		}
	}

	slices.SortFunc(res, func(a, b expensiveFn) bool {
		// sort high -> low
		return b.numVals < a.numVals
	})

	return res
}
