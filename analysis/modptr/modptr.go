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

// Package modptr implements an analysis that detects all modifications to a pointer-like value.
package modptr

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/internal/analysisutil"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
)

// Result represents the result of the analysis.
type Result struct {
	// Modifications represents the instructions that modify the entrypoint.
	Modifications map[Entrypoint]map[ssa.Instruction]struct{}
}

// Entrypoint represents an Entrypoint to the analysis.
// This is an argument to a function call specified by the configuration file's
// modval analysis spec.
type Entrypoint struct {
	// Val is the argument value.
	Val ssa.Value
	// Call is the call instruction containing the argument.
	Call ssa.CallInstruction
	// Pos is the position of the callsite, not the argument value itself.
	Pos token.Position
}

// Analyze runs the analysis on lp.
func Analyze(cfg *config.Config, lp analysis.LoadedProgram, ptrRes *pointer.Result) (Result, error) {
	modifications := map[Entrypoint]map[ssa.Instruction]struct{}{}
	prog := lp.Program
	log := config.NewLogGroup(cfg)

	// pre-allocate maps for speed
	numPtrs := len(ptrRes.Queries) + len(ptrRes.IndirectQueries)
	reachable := lang.CallGraphReachable(ptrRes.CallGraph, false, false)
	ac := &aliasCache{
		prog:                         prog,
		ptrRes:                       ptrRes,
		reachableFuncs:               reachable,
		globalPtrsTo:                 make(map[ssa.Value][]pointer.Pointer),
		globalValsThatAlias:          make(map[pointer.Pointer]map[ssa.Value]struct{}, numPtrs),
		computedAliasedValuesForFunc: make(map[pointer.Pointer]map[*ssa.Function]struct{}),
		computedTransitiveAliases:    make(map[ssa.Value]struct{}),
	}
	progTypes := prog.RuntimeTypes()
	tc := &typeCache{
		progTypes:  progTypes,
		implements: make(map[*types.Interface][]types.Type),
		basic:      make(map[types.Type][]*types.Basic),
	}
	c := &cache{
		aliasCache: ac,
		typeCache:  tc,
	}

	var errs []error
	for _, spec := range cfg.ModificationTrackingProblems {
		if err := analyze(log, spec, c, modifications); err != nil {
			errs = append(errs, fmt.Errorf("analysis failed for spec %v: %v", spec, err))
		}
	}

	return Result{
		Modifications: modifications,
	}, errors.Join(errs...)
}

// analyze runs the analysis for a single spec and adds the write instructions to modifications.
func analyze(log *config.LogGroup, spec config.ModValSpec, c *cache, modifications map[Entrypoint]map[ssa.Instruction]struct{}) error {
	var errs []error
	entrypoints := c.findEntrypoints(spec)
	for entry := range entrypoints {
		val := entry.Val
		if val.Type() == nil {
			errs = append(errs, fmt.Errorf("entrypoint %v type is nil: %T\n", val, val))
			continue
		}
		if !pointer.CanPoint(val.Type()) {
			errs = append(errs, fmt.Errorf("entrypoint is a non-pointer type: %v", val.Type()))
			continue
		}
		log.Infof("ENTRY: %v of %v in %v at %v\n", val.Name(), entry.Call, val.Parent(), entry.Pos)

		// Only analyze the functions can modify the entrypoint.
		//
		// Crucially, "reachable" functions do not exclude functions that are
		// filtered by the config. This is because filtered functions may
		// produce intermediate pointers that may alias pointers used in
		// unfiltered functions.
		entryTypes := c.typeCache.allBasicTypes(val.Type())
		log.Debugf("\tentrypoint types: %v\n", entryTypes)
		fnsToAnalyze := make(map[*ssa.Function]bool)
		fnsToAnalyze[val.Parent()] = true
		for fn := range c.reachableFuncs {
			if !isFnPure(c.typeCache, entryTypes, fn) {
				fnsToAnalyze[fn] = true
			}
		}
		log.Debugf("\tnumber of functions to analyze: %v\n", len(fnsToAnalyze))
		toAnalyze := make(map[*ssa.Function]*funcToAnalyze, len(fnsToAnalyze))
		numVals := 0
		numInstrs := 0
		for fn := range fnsToAnalyze {
			af := newFuncToAnalyze(c.typeCache, entryTypes, fn)
			toAnalyze[fn] = af
			numVals += len(af.vals)
			numInstrs += len(af.instrs)
		}
		log.Debugf("\tnumber of vals to analyze: %v\n", numVals)
		log.Debugf("\tnumber of write instructions to analyze: %v\n", numInstrs)

		s := &state{
			cache:          c,
			log:            log,
			spec:           spec,
			writesToAlias:  make(map[ssa.Value]map[ssa.Instruction]struct{}),
			funcsToAnalyze: toAnalyze,
		}

		// report functions with a high number of SSA values for debugging purposes
		if log.LogsDebug() {
			fns := mostExpensiveFns(c.typeCache, entryTypes, fnsToAnalyze)
			if len(fns) > 0 {
				log.Debugf("\tmost expensive functions (name | signature | number of values):\n")
				for _, ef := range fns {
					log.Debugf("\t\t%v | %v | %v\n", ef.fn.String(), ef.fn.Signature, ef.numVals)
				}
			}
		}

		ptrs := s.transitivePointersTo(val)
		s.findWritesToAliases(ptrs)
		for _, instrs := range s.writesToAlias {
			for instr := range instrs {
				if _, ok := modifications[entry]; !ok {
					modifications[entry] = make(map[ssa.Instruction]struct{})
				}

				modifications[entry][instr] = struct{}{}
			}
		}
	}

	return errors.Join(errs...)
}

// state represents the analysis state.
// This tracks writes to a single value (entrypoint).
type state struct {
	*cache
	log  *config.LogGroup
	spec config.ModValSpec

	funcsToAnalyze map[*ssa.Function]*funcToAnalyze
	// writesToAlias stores the set of instructions that write to an alias
	// (SSA value).
	writesToAlias map[ssa.Value]map[ssa.Instruction]struct{}
}

// findWritesToAliases adds all write instructions to transitive aliases of
// ptrs to s.writesToAlias.
//
// Algorithm:
//  1. Compute all values reachable from the entrypoint that transitively
//     may-alias ptrs. This initializes the global may-alias cache.
//  2. Filter all may-aliased values that do not need to be considered as
//     aliases of the entrypoint because of the configuraton spec.
//  3. For every instruction reachable from the entrypoint, if the lvalue is an
//     alias, or the instruction allocates a value to an alias, then the alias
//     has been "modified".
func (s *state) findWritesToAliases(ptrs []pointer.Pointer) {
	log := s.log
	for _, ptr := range ptrs {
		allAliases := s.allAliasesOf(ptr)
		for alias := range allAliases {
			if s.shouldFilterValue(alias) {
				log.Tracef("alias %v filtered by spec\n", alias)
				delete(allAliases, alias)
			}
			// special case: *ssa.MakeInterface aliases rvalue
			if mi, ok := alias.(*ssa.MakeInterface); ok {
				allAliases[mi.X] = struct{}{}
			}
		}
		for alias := range allAliases {
			s.addTransitiveMayAliases(alias, allAliases)
		}

		for alias := range allAliases {
			log.Tracef("alias %v: %v in %v\n", alias.Name(), alias, alias.Parent())
			if _, ok := s.writesToAlias[alias]; !ok {
				s.writesToAlias[alias] = make(map[ssa.Instruction]struct{})
			}

			for _, rfn := range s.funcsToAnalyze {
				for instr := range rfn.instrs {
					allocs := false
					if alloc, ok := instr.(*ssa.Alloc); ok {
						allocs = alloc == alias
					}

					if _, ok := lang.InstrWritesToVal(instr, alias); ok || allocs {
						log.Tracef("instr %v writes to alias %v\n", instr, alias)
						s.writesToAlias[alias][instr] = struct{}{}
					}
				}
			}
		}
	}
}

// addTransitiveMayAliases adds all transitive aliases of alias to allAliases.
func (s *state) addTransitiveMayAliases(alias ssa.Value, allAliases map[ssa.Value]struct{}) {
	if _, ok := s.computedTransitiveAliases[alias]; ok {
		return
	}

	visit := s.transitivePointersTo(alias)
	seen := make(map[pointer.Pointer]struct{})
	for len(visit) > 0 {
		cur := visit[len(visit)-1]
		visit = visit[0 : len(visit)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		newAliases := s.allAliasesOf(cur)
		for a := range newAliases {
			if _, ok := allAliases[a]; ok || s.shouldFilterValue(a) {
				continue
			}

			allAliases[a] = struct{}{}
			s.log.Tracef("found transitive alias of %v: %v (%v) in %v\n", alias, a, a.Name(), a.Parent())
			for _, next := range s.transitivePointersTo(a) {
				visit = append(visit, next)
			}
		}
	}

	s.computedTransitiveAliases[alias] = struct{}{}
}

// shouldFilterValue returns true if the value should be filtered
// according to the spec.
func (s *state) shouldFilterValue(val ssa.Value) bool {
	return val == nil || doesConfigFilterFn(s.spec, val.Parent())
}

func (s *state) transitivePointersTo(val ssa.Value) []pointer.Pointer {
	if ptrs, ok := s.aliasCache.globalPtrsTo[val]; ok {
		return ptrs
	}

	stack := lang.FindAllPointers(s.aliasCache.ptrRes, val)
	seen := make(map[pointer.Pointer]struct{})
	var ptrs []pointer.Pointer
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[0 : len(stack)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		for _, label := range cur.PointsTo().Labels() {
			val := label.Value()
			if val == nil || val.Parent() == nil {
				continue
			}

			labelPtrs := lang.FindAllPointers(s.aliasCache.ptrRes, val)
			stack = append(stack, labelPtrs...)
			for _, ptr := range labelPtrs {
				ptrs = append(ptrs, ptr)
			}
		}
	}

	s.aliasCache.globalPtrsTo[val] = ptrs
	return ptrs
}

// allAliasesOf computes all the values that are in the points-to set of a
// pointer that transitively may-alias ptr.
// This function only analyzes the values reachable from a single analysis
// entrypoint.
func (s *state) allAliasesOf(ptr pointer.Pointer) map[ssa.Value]struct{} {
	// Even if the aliases of ptr are cached, the cache may have missed some,
	// therefore the rest need to be analyzed.
	// This is a global cache so some aliased values may not be reachable from the entrypoint
	// and therefore those values do not need to be analyzed.
	cachedAliases, hasCachedAliases := s.aliasCache.globalValsThatAlias[ptr]
	aliases := make(map[ssa.Value]struct{}, len(cachedAliases))
	if hasCachedAliases && len(cachedAliases) > 0 {
		for v := range cachedAliases {
			if _, ok := s.funcsToAnalyze[v.Parent()]; !ok {
				continue
			}

			aliases[v] = struct{}{}
		}
	}

	for fn, rfn := range s.funcsToAnalyze {
		if _, ok := s.computedAliasedValuesForFunc[ptr][fn]; ok {
			// skip if we already analyzed the function's aliased values
			continue
		}

		for val := range rfn.vals {
			if _, ok := aliases[val]; ok {
				continue
			}

			ptrs := s.transitivePointersTo(val)
			for _, valPtr := range ptrs {
				if valPtr.MayAlias(ptr) {
					aliases[val] = struct{}{}
					break
				}
			}
		}

		if _, ok := s.computedAliasedValuesForFunc[ptr]; !ok {
			s.computedAliasedValuesForFunc[ptr] = make(map[*ssa.Function]struct{})
		}
		s.computedAliasedValuesForFunc[ptr][fn] = struct{}{}
	}

	// update the global cache with the newly-computed aliases
	if !hasCachedAliases {
		s.aliasCache.globalValsThatAlias[ptr] = make(map[ssa.Value]struct{}, len(aliases))
	}
	for val := range aliases {
		s.aliasCache.globalValsThatAlias[ptr][val] = struct{}{}
	}

	return aliases
}

// cache represents a "global" cache for the analysis.
type cache struct {
	*aliasCache
	*typeCache
}

// aliasCache represents a "global" cache for transitive pointers and aliases.
//
// The analysis only searches for pointers and aliases that are reachable from a
// single entrypoint, but this cache helps if there are multiple entrypoints
// that need alias information computed from previous entrypoints.
type aliasCache struct {
	prog           *ssa.Program
	ptrRes         *pointer.Result
	reachableFuncs map[*ssa.Function]bool
	// globalPtrsTo stores the set of program-wide transitive pointers to a value.
	globalPtrsTo map[ssa.Value][]pointer.Pointer
	// globalValsThatAlias stores the program-wide set of values that are in the
	// points-to set of a pointer that may alias an entrypoint.
	globalValsThatAlias          map[pointer.Pointer]map[ssa.Value]struct{}
	computedAliasedValuesForFunc map[pointer.Pointer]map[*ssa.Function]struct{}
	computedTransitiveAliases    map[ssa.Value]struct{}
}

// findEntrypoints returns all the analysis entrypoints specified by spec.
func (ac *aliasCache) findEntrypoints(spec config.ModValSpec) map[Entrypoint]struct{} {
	entrypoints := make(map[Entrypoint]struct{})
	for fn, node := range ac.ptrRes.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		if _, ok := ac.reachableFuncs[fn]; !ok {
			continue
		}

		for _, inEdge := range node.In {
			if inEdge == nil || inEdge.Site == nil {
				continue
			}

			entry, ok := ac.findEntrypoint(spec, inEdge.Site.Value())
			if !ok {
				continue
			}

			entrypoints[entry] = struct{}{}
		}
	}

	return entrypoints
}

func (ac *aliasCache) findEntrypoint(spec config.ModValSpec, call *ssa.Call) (Entrypoint, bool) {
	// use analysisutil entrypoint logic to take care of function aliases and
	// other edge-cases
	if !analysisutil.IsEntrypointNode(ac.ptrRes, call, spec.IsValue) {
		return Entrypoint{}, false
	}

	callPos := ac.prog.Fset.Position(call.Pos())
	for _, cid := range spec.Values {
		// TODO parse label beforehand to prevent panics
		idx, err := strconv.Atoi(cid.Label)
		if err != nil {
			err := fmt.Errorf("cid label is not a valid argument index: %v", err)
			panic(err)
		}
		if idx < 0 {
			err := fmt.Errorf("cid label is not a valid argument index: %v < 0", idx)
			panic(err)
		}

		args := lang.GetArgs(call)
		if len(args) < idx {
			fmt.Printf("arg index: %v < want %v\n", len(args), idx)
			return Entrypoint{}, false
		}

		val := args[idx]
		return Entrypoint{Val: val, Call: call, Pos: callPos}, true
	}

	return Entrypoint{}, false
}

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

type funcToAnalyze struct {
	instrs map[ssa.Instruction]struct{}
	vals   map[ssa.Value]struct{}
}

func newFuncToAnalyze(tc *typeCache, entryTypes []*types.Basic, fn *ssa.Function) *funcToAnalyze {
	vals := make(map[ssa.Value]struct{})
	addValuesOfFn(tc, entryTypes, fn, vals)
	instrs := make(map[ssa.Instruction]struct{})
	lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
		if instr == nil || instr.Parent() == nil {
			return
		}

		switch instr.(type) {
		case *ssa.Alloc, *ssa.Store, *ssa.MapUpdate, *ssa.Send:
			instrs[instr] = struct{}{}
		}
	})

	return &funcToAnalyze{
		vals:   vals,
		instrs: instrs,
	}
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
	"crypto/internal/edwards25519": {},
	"crypto/internal/nistec":       {},
	"crypto/internal/nistec/fiat":  {},
	"errors":                       {},
	"fmt":                          {},
	"internal":                     {},
	"math/big":                     {},
	"reflect":                      {}, // we assume that reflection is not used to modify aliases
	"regexp":                       {},
	"runtime":                      {},
	"strconv":                      {},
	"strings":                      {},
	"sync":                         {},
	"syscall":                      {},
	"time":                         {},
	"unsafe":                       {}, // we assume that unsafe is not used to modify aliases
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

// doesConfigFilterFn returns true if f should be filtered according to spec.
func doesConfigFilterFn(spec config.ModValSpec, f *ssa.Function) bool {
	for _, filter := range spec.Filters {
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}
