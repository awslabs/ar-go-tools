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

/*
Souffle-based static race detector for Go.

The program iterates through the SSA for the given Go module or Go source file,
and produces fact files that encode various information about the Go source
program. These fact files are later consumed by Souffle Datalog when computing
other facts, e.g., the point-to information between memory allocations,
which functions are reachable, possible data races. Finally, the Souffle-generated
facts are read back into the driver which prints user-friendly analysis results
onto screen.

For easier debugging, a _generated_facts.log file is also created when the
analysis driver runs, that illustrate the line-by-line correspondence between
an original SSA instruction and the generated facts about it.

Usage:

go run main.go [flags] [source ...]

The flags are:

-mod
The path to the Go module to be analyzed.

-ssaline
Print the line-by-line SSA and the generated fact, for debugging.

-ssafunc
Before printing the debugging information for each instruction in a function,
print SSA for the whole function using the Go ssa package.

-souffle-path
Path to the souffle executable.

-souffle-analysis
Path to the main souffle analysis (.dl).

-output
Path to a directory used to store the generated facts.

-roots-path
Provide a csv file for the entry functions to analyze.
Each function is on a separate line.
A default root file would be a csv with just one line that indicates
analysis starts with the main function in the main package, or "main.main".

-threads
Provide number of threads that is used to run the Souffle engine.
*/
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// TODO: handle errors properly in all places

// Global variables for command line flags
var modulePath string
var printLineByLine bool
var printSSAForFunc bool

var outputPath string
var souffleExecPath string
var souffleAnalysisPath string
var souffleFactsDir string
var souffleOutputDir string
var numSouffleThreads int
var rootFunctionsFilePath string

// souffle analysis result file to be read
func souffleOutputFileName(uuid string) string { return fmt.Sprintf("race-%s.csv", uuid) }

// file name to output for the SSA
func ssaOutputFileName(uuid string) string { return fmt.Sprintf("_ssa-%s.log", uuid) }

// detailed log file for debugging fact generation
func factGenerationLogName(uuid string) string { return fmt.Sprintf("_generated_facts-%s.log", uuid) }

// An arbitrary program counter to represent different SSA locations.
var programCounter = 0

// Distinguish between different allocation sites.
var allocSiteCounter = 0

// A mapping between the manually created SSA location and source location.
var sourceLocation = make(map[int]*token.Pos)

// Writers for printing Souffle facts.
var factWriters = make(map[string]*os.File)

// A mapping between call instructions and their corresponding SSA locations.
// This is needed to use CHA call graph inside the Datalog analysis.
var ssaLocForCallInst = make(map[*ssa.CallCommon]int)

// Whether a call instruction is a Go or not
var callInstIsGo = make(map[*ssa.CallCommon]bool)

func init() {
	flag.StringVar(&modulePath, "mod", "", "module path to analyze")
	flag.BoolVar(&printLineByLine, "ssaline", false, "print line by line SSA")
	flag.BoolVar(&printSSAForFunc, "ssafunc", false, "print SSA for each function")
	flag.StringVar(&souffleExecPath, "souffle-path", "", "path to the souffle executable")
	flag.StringVar(&souffleAnalysisPath, "souffle-analysis", "",
		"path to the souffle analysis source file")
	flag.StringVar(&outputPath, "output", ".", "output directory for the facts")
	flag.IntVar(&numSouffleThreads, "threads", 4,
		"number of parallel threads when invoking Souffle")
	flag.StringVar(&rootFunctionsFilePath, "roots-path", "",
		"path to a csv file that contains one root function as the starting point of the analysis per line")
	log.SetOutput(io.Discard)
}

// Compute SSA program and a list of all the packages for the given args.
func createSSA(args []string) (*ssa.Program, []*ssa.Package, error) {
	conf1 := packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  modulePath,
	}
	pkgs, err := packages.Load(&conf1, args...)
	if err != nil {
		return nil, nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("no packages")
	}

	if len(pkgs[0].Errors) > 0 {
		log.Printf("err loading packages %s", pkgs[0].Errors[0].Msg)
	}

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, 0)
	for i, p := range ssaPkgs {
		if p == nil {
			return nil, nil, fmt.Errorf("cannot build SSA for package %s", pkgs[i])
		}
	}

	ssaProg.Build()
	return ssaProg, ssaPkgs, nil
}

// Get a qualified name for each local variable by prefixing with the name of the enclosing function.
func getQualifiedName(parentName, varName string) string {
	return parentName + ":" + varName
}

// Get a qualified name for global by prefixing the package name
func getQualifiedNameGlobal(pkgName, varName string) string {
	return pkgName + "@" + varName
}

// printSSAValue returns the textual representation of an SSA value.
// The locals get a prefix with the enclosing function name.
// The globals get a prefix with the enclosing package name.
func printSSAValue(pv *ssa.Value) string {
	v := *pv
	switch vt := v.(type) {
	case *ssa.Const:
		intVal, isInt := checkIfConst(pv)
		if !isInt {
			return "Constant"
		}
		return "ConstInt" + strconv.Itoa(int(intVal))
	case *ssa.Global:
		pkgName := vt.Pkg.Pkg.Name()
		return getQualifiedNameGlobal(pkgName, v.Name())
	}

	if v.Parent() != nil { // local
		return getQualifiedName(getFuncName(v.Parent()), v.Name())
	}
	// TODO: what to do here
	return v.Name()
}

// getFuncName returns a qualified name for a function by prefixing the enclosing package name.
func getFuncName(f *ssa.Function) string {
	if f.Pkg != nil {
		if f.Pkg.Pkg != nil {
			return f.Pkg.Pkg.Name() + "." + f.Name()
		}
	}
	return f.Name()
}

// printFact prints facts about a certain relation with arbitrary arity.
func printFact(relationName string, additionalArgs ...any) {
	// Each fact file gets its own writer that is created just once and reused later.
	w, ok := factWriters[relationName]
	factsFileName := "_" + relationName + ".facts"
	path := filepath.Join(outputPath, factsFileName)
	if !ok {
		// Create file for the first time a relation is written to.
		factsFile, err := os.Create(path)
		if err != nil {
			log.Fatal(err)
		}
		factWriters[relationName] = factsFile
		w = factsFile
	} else {
		// Need to append to a file that has been created on disk.
		w.Close()
		factsFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		factWriters[relationName] = factsFile
		w = factsFile
	}

	// Write facts with arbitrary arity, seperated by tabs.
	var sb strings.Builder
	if len(additionalArgs) > 0 {
		for _, arg := range additionalArgs {
			sb.WriteString(fmt.Sprint(arg, "\t"))
		}
		sb.WriteString("\n")
		fmt.Fprint(w, sb.String())
	}
}

// processCallCommon extracts from SSA information about call commons.
//
// A call common represents either a dynamic call or invoke, or a static call.
// For a dynamic call, we need to record:
//   - the receiver object
//   - the function signature, which includes the function name and the types of arguments
//
// For a function call that is resolved statically, we distinguish between:
//   - built-in functions
//   - normal function
//   - closure functions
func processCallCommon(cc *ssa.CallCommon) (callKind, funcName, receiver string,
	receiverType types.Type, argTypes, sigArgTypes []types.Type, actualArgs []string) {
	f := cc.Value
	for _, arg := range cc.Args {
		argName := printSSAValue(&arg)
		actualArgs = append(actualArgs, argName)
		argTypes = append(argTypes, arg.Type())
	}

	if cc.IsInvoke() {
		callKind = "Invoke"
		receiver = printSSAValue(&f)
		funcName = cc.Method.FullName()
		sig := cc.Signature()

		receiverType = sig.Recv().Type()
		params := sig.Params()
		for i := 0; i < params.Len(); i++ {
			sigArgTypes = append(sigArgTypes, params.At(i).Type())
		}
	} else {
		callKind = "StaticCall"
		switch funcKind := f.(type) {
		case *ssa.Builtin:
			callKind = "Builtin" + funcKind.Name()
		case *ssa.Function:
			funcName = getFuncName(funcKind)
		case *ssa.MakeClosure:
			switch closureFunc := funcKind.Fn.(type) {
			case *ssa.Function:
				funcName = getFuncName(closureFunc)
			default:
				log.Println("Cannot resolve called function at: ", cc.String(), " in ", cc.Pos())
			}
		}
	}
	return
}

// printType prints a string representation of a Go type.
// Distinguish between value types, reference types, pointer types, and interface types.
// TODO: refactor the design of this function and the overall text-based interface for types
func printType(t types.Type) (typeStr, typeKind, elemType string) {
	typeStr = t.String()
	if typeStr == "iter" {
		typeKind = "iter"
		elemType = "NA"
		return
	}
	getElemType := func(et types.Type) (elemTypeStr string) {
		switch et.Underlying().(type) {
		case *types.Struct:
			elemTypeStr = "Struct"
		case *types.Interface:
			elemTypeStr = "Interface"
		case *types.Pointer:
			elemTypeStr = "Pointer"
		case *types.Map:
			elemTypeStr = "Map"
		case *types.Slice:
			elemTypeStr = "Slice"
		case *types.Array:
			elemTypeStr = "Array"
		case *types.Chan:
			elemTypeStr = "Chan"
		default:
			elemTypeStr = "Value"
		}
		return elemTypeStr
	}

	switch vt := t.Underlying().(type) {
	case *types.Interface:
		typeKind = "Interface"
		elemType = "NA"
	case *types.Pointer:
		typeKind = "Pointer"
		elemType = getElemType(vt.Elem())
	case *types.Struct:
		typeKind = "Struct"
		elemType = "NA"
	case *types.Map:
		typeKind = "Map"
		elemType = getElemType(vt.Elem())
	case *types.Slice:
		typeKind = "Slice"
		elemType = getElemType(vt.Elem())
	case *types.Chan:
		typeKind = "Chan"
		elemType = "NA"
	default:
		typeKind = "Value"
		elemType = "NA"
	}
	return
}

// checkIfConst checks if an SSA value represents a constant int64
func checkIfConst(v *ssa.Value) (val int64, ok bool) {
	switch vt := (*v).(type) {
	case *ssa.Const:
		c := vt.Value
		if c == nil {
			ok = false
			return
		}
		kindStr := c.Kind().String()
		if kindStr != "Int" {
			ok = false
			return
		}
		val, ok = constant.Int64Val(c)
		return
	}
	ok = false
	return
}

// processFunction prints facts about an SSA function:
// - Formal args
//   - Formal return values
//   - Artificially created entry point and return points
//   - Facts about each instruction inside the function
//
//gocyclo:ignore
func processFunction(debugFactWriter io.Writer, ssaWriter io.Writer, f *ssa.Function) {

	funcName := getFuncName(f)
	log.Println("printing facts for function: ", funcName)

	fmt.Fprintf(debugFactWriter, "\n\n// func %s\n", funcName)
	fmt.Fprintf(ssaWriter, "\n\n\t\t// func %s\n", funcName)

	if printSSAForFunc {
		fmt.Fprintf(debugFactWriter, "/*\n")
		f.WriteTo(debugFactWriter)
		fmt.Fprintf(debugFactWriter, "*/\n\n")
	}

	// Each instruction has a global program location associated with it
	// We also introduce a start node and a return node, that makes the analysis
	// cleaner
	programCounter++
	funcStartNode := programCounter

	programCounter++
	funcReturnNode := programCounter

	printFact("Function", funcName, len(f.Blocks), funcStartNode, funcReturnNode)

	fmt.Fprintln(debugFactWriter, "// Function", funcName, "num of blocks:", len(f.Blocks), "artificial start loc:", funcStartNode, "artificial return loc:", funcReturnNode)
	fmt.Fprintln(ssaWriter, "\t\t", funcName, f.Signature.String(), "\n\t\tstart loc:", funcStartNode, "return loc:", funcReturnNode)

	// Print facts about each formal parameter of the function
	for paramInd, param := range f.Params {
		paramName := getQualifiedName(funcName, param.Name())
		fmt.Fprintf(debugFactWriter, "FormalParam(%s, %d, %s)\n", funcName, paramInd, paramName)
		paramTypeStr, paramTypeKind, paramElemType := printType(param.Type())
		printFact("FormalParam", funcName, paramInd, paramName, paramTypeStr, paramTypeKind, paramElemType)
	}

	// Print facts about each free var in a closure function
	for fvInd, fv := range f.FreeVars {
		fvName := getQualifiedName(funcName, fv.Name())
		fmt.Fprintf(debugFactWriter, "FreeVar(%s, %d, %s)\n", funcName, fvInd, fvName)
		typeStr, typeKind, elemType := printType(fv.Type())
		printFact("FreeVar", funcName, fvInd, fvName, typeStr, typeKind, elemType)

	}

	// Iterates through each basic block (BB) of the function
	for bbInd, bb := range f.Blocks {
		// currently we are not modeling the panic-recover control flow
		if bb == bb.Parent().Recover {
			continue
		}
		fmt.Fprintf(debugFactWriter, "BB(%s, %d, %d)\n", funcName, bbInd, len(bb.Instrs))
		printFact("BB", funcName, bbInd, len(bb.Instrs))
		for succInd, succ := range bb.Succs {
			fmt.Fprintf(debugFactWriter, "BBSucc(%s, %d, %d)\n", funcName, bbInd, succ.Index)
			printFact("BBSucc", funcName, bbInd, succInd, succ.Index)

		}
		// Iterates through each instruction in a BB
		for instInd, inst := range bb.Instrs {

			// Associate a new program location with this instruction
			programCounter++

			// Go SSA Instructions do not always have a source location, since they
			// might not correspond directly to the Go source code.
			if inst.Pos().IsValid() {
				p := inst.Pos()
				sourceLocation[programCounter] = &p
			}

			// The instruction might have an LHS, in which case it is a value.
			// Also print the LHS local variable in this scenario.
			switch instIsValue := inst.(type) {
			case ssa.Value:
				typeStr, typeKind, elemType := printType(instIsValue.Type())
				printFact("LocalVarType", getQualifiedName(funcName, instIsValue.Name()), typeStr, typeKind, elemType)
				if printLineByLine {
					fmt.Fprintf(debugFactWriter, "// %s = %s\n", instIsValue.Name(), inst.String())
					fmt.Fprintf(ssaWriter, "%d\t\t%s = %s\n", programCounter, instIsValue.Name(), inst.String())
				}
			default:
				if printLineByLine {
					fmt.Fprintf(debugFactWriter, "// %s\n", inst.String())
					fmt.Fprintf(ssaWriter, "%d\t\t%s\n", programCounter, inst.String())

				}
			}

			// Print facts about an instruction.
			// This is declared as a closure function since this automatically captures
			// variables pointing to the enclosing function, enclsoing basic block, etc.
			// which makes expressing the location of the instruction easier.
			printInstFact := func(instName string, additionalArgs ...any) {
				factStr := fmt.Sprintf("%s(%d, %s, %d, %d", instName, programCounter, funcName, bbInd, instInd)
				var sb strings.Builder
				for _, arg := range additionalArgs {
					sb.WriteString(fmt.Sprint(", ", arg))
				}
				sb.WriteString(")")
				fmt.Fprintln(debugFactWriter, factStr+sb.String())

				// The Inst relation is just used for computing control flow facts, which does
				// not need to know what the instruction actually is.
				argsList1 := []interface{}{programCounter, funcName, instName, bbInd, instInd}
				printFact("Inst", argsList1...)

				// Print detailed information about the particular instruction type.
				argsList2 := []interface{}{programCounter, funcName, bbInd, instInd}
				allArgs := append(argsList2, additionalArgs...)
				printFact(instName, allArgs...)
			}

			// Prints facts about a call instruction.
			// As in the case for handling call commons, the call can be statically resolved
			// or an invoke.
			processCallInst := func(callInstName string, retReg *ssa.Call, cc *ssa.CallCommon) {
				ssaLocForCallInst[cc] = programCounter
				if callInstName == "Go" {
					callInstIsGo[cc] = true
				} else {
					callInstIsGo[cc] = false
				}
				callKind, calleeName, receiver, receiverType, argTypes, _, actualArgs := processCallCommon(cc)
				if callKind == "StaticCall" {
					printInstFact("StaticCall", callInstName, calleeName)
				} else if callKind == "Invoke" {
					printInstFact("Invoke", callInstName, receiver, calleeName)
					typeStr, typeKind, elemType := printType(receiverType)
					printInstFact("InvokeFunctionWithReceiverType", callInstName, receiver, typeStr, typeKind, elemType)
				}
				for argInd, actualArg := range actualArgs {
					argTypeStr, argTypeKind, argElemType := printType(argTypes[argInd])
					if calleeName != "sync.Add" {
						printInstFact("ActualArg", callInstName, calleeName, argInd, actualArg, argTypeStr, argTypeKind, argElemType)
					} else {
						printInstFact("ActualArg", callInstName, calleeName, argInd, actualArg, argTypeStr, argTypeKind, argElemType)

					}
				}

				// If the call instruction has an actual return register that stores the return
				// values, then print facts about it. The return register can be a single value,
				// or a tuple.
				if retReg != nil {
					returnRegName := getQualifiedName(funcName, retReg.Name())
					typeStr, typeKind, elemType := printType(retReg.Type())
					returnTupleLen := cc.Signature().Results().Len()
					printInstFact("ActualReturn", callInstName, returnRegName,
						returnTupleLen, typeStr, typeKind, elemType)
				}
			}

			// The main type switch for printing facts about each SSA instruction.
			switch instKind := inst.(type) {

			case *ssa.Alloc:
				// For allocations, record its source location and a unique global ID for it.
				log.Println("alloc instruction")
				allocSiteCounter++
				varName := getQualifiedName(funcName, instKind.Name())
				printInstFact("Alloc", varName, allocSiteCounter)

			case *ssa.Store:
				// Record information about stores: *to = from
				log.Println("store instruction")
				storingFromStr := printSSAValue(&instKind.Val)
				storingIntoStr := printSSAValue(&instKind.Addr)
				printInstFact("Store", storingIntoStr, storingFromStr)

			case *ssa.UnOp:
				//	A unary operation can be
				// 		- a load: reg = *rhs
				//		- a receive from channel: reg = <-rhs
				log.Println("unop instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				rhs := printSSAValue(&instKind.X)
				switch instKind.Op {
				// taking the address of RHS
				case token.MUL:
					printInstFact("Load", regName, rhs)
				case token.ARROW:
					printInstFact("Receive", regName, rhs)
				}

			case *ssa.Go:
				// A Go instruction is also a call instruction but creates a new thread.
				log.Println("go instruction")
				processCallInst("Go", instKind.Value(), instKind.Common())

			case *ssa.Call:
				// A normal call instruction.
				log.Println("call instruction")
				processCallInst("Call", instKind.Value(), instKind.Common())

			case *ssa.Defer:
				log.Println("defer instruction")
				processCallInst("Defer", instKind.Value(), instKind.Common())

			case *ssa.Field:
				log.Println("field instruction")
				varName := getQualifiedName(funcName, instKind.Name())
				structBase := printSSAValue(&instKind.X)
				printInstFact("Field", varName, structBase, instKind.Field)

			case *ssa.FieldAddr:
				log.Println("fieldaddr instruction")
				varName := getQualifiedName(funcName, instKind.Name())
				structBase := printSSAValue(&instKind.X)
				printInstFact("FieldAddr", varName, structBase, instKind.Field)

			case *ssa.If:
				// We only cares about the control flow for the if instruction, but not
				// the conditions.
				log.Println("If instruction")
				printInstFact("If", bb.Succs[0].Index, bb.Succs[1].Index)

			case *ssa.Jump:
				// Unconditional jumps.
				log.Println("Jump instruction")
				printInstFact("Jump", bb.Succs[0].Index)

			case *ssa.Phi:
				// For phi instructions, we care about which values flow back to the
				// register on the LHS.
				log.Println("Phi instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				for eInd, edge := range instKind.Edges {
					incomingValName := printSSAValue(&edge)
					printInstFact("Phi", regName, eInd, incomingValName)
				}

			case *ssa.Lookup:
				log.Println("Lookup instruction")

			case *ssa.MakeChan:
				// Need to create facts about channel creation, since the analysis relies on
				// analyzing channel communications to compute ordering relations.
				log.Println("MakeChan instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				channelCapacity := instKind.Size
				capacity, capacityIsInt := checkIfConst(&channelCapacity)
				if capacityIsInt {
					printInstFact("MakeChan", regName, capacity)
				} else {
					printInstFact("MakeChan", regName, -1)

				}

			case *ssa.MakeClosure:
				// Creation of function closures.
				log.Println("MakeClosure instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				switch closureFunc := instKind.Fn.(type) {
				case *ssa.Function:
					fName := getFuncName(closureFunc)
					printInstFact("MakeClosure", regName, fName)
					// What variables in the parent function does the closure function bind.
					for bindingInd, bindingArg := range instKind.Bindings {
						printFact("ClosureBindsFreeVar", fName, bindingInd, printSSAValue(&bindingArg))
						fmt.Fprintf(debugFactWriter, "ClosureBindsFreeVar(%s, %d, %s)\n", fName, bindingInd, printSSAValue(&bindingArg))
					}
				}

			case *ssa.Extract:
				// Extract a value at index from a tuple.
				log.Println("Extract instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				tupleName := printSSAValue(&instKind.Tuple)
				printInstFact("ExtractTuple", regName, tupleName, instKind.Index)

			case *ssa.MakeSlice:
				log.Println("MakeSlice instruction")

			case *ssa.Slice:
				log.Println("Slice instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				rhs := printSSAValue(&instKind.X)
				printInstFact("Slice", regName, rhs)

			case *ssa.SliceToArrayPointer:
				log.Println("SliceToArrayPointer instruction")

			case *ssa.Index:
				// Process an indexing operation for a slice: regName = baseArray[ind].
				// Only record the actual index if it is a constant known statically.
				log.Println("index instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				var canResolveInd bool
				var resolvedInd int64
				baseArray := printSSAValue(&instKind.X)
				ind := instKind.Index
				switch indType := ind.(type) {
				case *ssa.Const:
					constInd := indType.Value
					resolvedInd, canResolveInd = constant.Int64Val(constInd)
				}
				if canResolveInd {
					printInstFact("LoadArrayConstIndex", regName, baseArray, resolvedInd)
				} else {
					printInstFact("LoadArrayAnyIndex", baseArray)
				}

			case *ssa.IndexAddr:
				// Compute the address of an element in a slice: regName = &baseArray[ind]
				log.Println("indexaddr instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				var canResolveInd bool
				var resolvedInd int64
				baseArray := printSSAValue(&instKind.X)
				ind := instKind.Index
				resolvedInd, canResolveInd = checkIfConst(&ind)
				if canResolveInd {
					printInstFact("AddrArrayConstIndex", regName, baseArray, resolvedInd)
				} else {
					printInstFact("AddrArrayAnyIndex", baseArray)
				}

			case *ssa.MakeMap:
				log.Println("MakeMap instruction")

			case *ssa.Next:
				log.Println("Next instruction")

			case *ssa.Range:
				log.Println("Range instruction")

			case *ssa.MakeInterface:
				// Interface creation.
				log.Println("MakeInterface instruction")
				regName := getQualifiedName(funcName, instKind.Name())
				rhs := printSSAValue(&instKind.X)
				printInstFact("MakeInterface", regName, rhs)

			case *ssa.ChangeInterface:
			case *ssa.ChangeType:
			case *ssa.Convert:

			case *ssa.BinOp:
				// Binary operation like: reg = x + y
				xName, yName := printSSAValue(&instKind.X), printSSAValue(&instKind.Y)
				printInstFact("BinOp", getQualifiedName(funcName, instKind.Name()), xName, yName)

			case *ssa.Return:
				// A return instruction in a function. Return always returns a tuple.
				log.Println("Return instruction")
				formalReturns := instKind.Results
				printInstFact("Return")
				printInstFact("FormalReturnTupleLen", len(formalReturns))
				for returnInd, returnVal := range formalReturns {
					returnValName := printSSAValue(&returnVal)
					printInstFact("FormalReturnTuple", returnValName, returnInd)
				}

			case *ssa.RunDefers:
				// Invoke the defers
				log.Println("RunDefers instruction")
				printInstFact("RunDefer")

			case *ssa.Select:
				// Waiting on several communications.
				log.Println("Select instruction")

			case *ssa.Send:
				// Sending on channel: channel.send(X)
				log.Println("Send instruction")
				channel, X := instKind.Chan, instKind.X
				printInstFact("Send", printSSAValue(&X), printSSAValue(&channel))
			}

		}
	}

}

// printEmptyFacts prints empty fact files for specific relations.
// Souffle errors on facts file that do not exist, create empty fact files for these relations.
// TODO: The list of all facts that might get read by souffle is currently not complete.
func printEmptyFacts() {
	mayBeEmpty := [...]string{
		"BBSucc", "ChaCallGraph", "StaticCall",
		"Invoke", "Return", "RunDefer", "Alloc",
		"Global", "Load", "Store", "MakeInterface",
		"Field", "FieldAddr", "StructFields",
		"FormalParam", "FreeVar", "ActualArg",
		"ClosureBindsFreeVar", "ActualReturnSingle",
		"ActualReturnTuple", "FormalReturnTuple",
		"FormalReturnTupleLen", "LocalVarType",
		"LoadArrayConstIndex", "LoadArrayAnyIndex",
		"AddrArrayConstIndex", "AddrArrayAnyIndex",
		"MakeChan", "Send", "Receive", "ActualReturn",
		"ExtractTuple", "Phi", "BinOp",
	}
	for _, f := range mayBeEmpty {
		printFact(f)
	}
}

// runSouffle invokes the Souffle executable on the analysis using the generated facts, capture the stdout
// of Souffle.
func runSouffle() {
	souffleFactsDir = "-F" + outputPath
	souffleOutputDir = "-D" + outputPath
	souffleThreads := "-j" + strconv.Itoa(numSouffleThreads)
	cmd := exec.Command(souffleExecPath,
		souffleFactsDir,
		souffleOutputDir,
		souffleThreads,
		souffleAnalysisPath)
	stdout, err := cmd.Output()
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	log.Println("Souffle stdout:", stdout)
}

// Try to find the corresponding source location given an SSA location.
func findSourceLocation(prog *ssa.Program, ssaLocation int) (originalSourceLocation string) {
	ssaLocStr := strconv.Itoa(ssaLocation)
	srcValuePos, ok := sourceLocation[ssaLocation]
	if !ok {
		return "Does not map back to source location, SSA location: " + ssaLocStr
	}
	originalSourceLocation = prog.Fset.Position(*srcValuePos).String()
	return originalSourceLocation + ", SSA location: " + ssaLocStr
}

// Parse the souffle output on the potential data races computed and print the results.
func parseSouffleOutput(stamp string, prog *ssa.Program) {
	// Find the souffle output file
	racesFilePath := outputPath + souffleOutputFileName(stamp)
	f, err := os.Open(racesFilePath)
	if err != nil {
		log.Fatal("Unable to read input file "+racesFilePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	csvReader.Comma = '\t'
	csvReader.FieldsPerRecord = -1
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+racesFilePath, err)
	}
	fmt.Println("=============")
	if len(records) == 0 {
		fmt.Println("No potential data race detected :)")
		return
	}

	// This function parses a text that represents a Datalog program location
	// and tries to map back to the source location
	interp := func(result string) (ans string) {
		result = strings.TrimSpace(result)
		if strings.HasPrefix(result, "$SSA") {
			ssaLoc, _ := strconv.Atoi(result[5 : len(result)-1])
			ans = findSourceLocation(prog, ssaLoc)
		} else if strings.HasPrefix(result, "$FunctionDecl") {
			parentLoc := strings.Index(result, "(")
			ans = "declaration of function: " + result[parentLoc+1:len(result)-1]
		} else if strings.HasPrefix(result, "$GlobalDecl") {
			ans = "global"
		} else {
			ans = "unknown SSA or source location"
		}
		return
	}

	for ind, record := range records {
		fmt.Println("Potential race pair #", ind)

		// Pretty-printing a memory access, displaying the thread information and
		// the computed source location
		printAccess := func(accessInd int, readWrite, srcLocStr, tid, thread string) {
			fmt.Printf("Access %d:\n", accessInd)
			var threadType, accessKind string
			if strings.HasPrefix(thread, "$RT") {
				threadType = "Root goroutine"
			} else if strings.HasPrefix(thread, "$Th") {
				threadType = "Spawned goroutine"
			} else if strings.HasPrefix(thread, "$GTh") {
				threadType = "Additional spawned goroutine"
			} else {
				threadType = "Global thread"
			}
			if threadType == "Spawned goroutine" || threadType == "Additional spawned goroutine" {
				threadSpawnLocStartInd := strings.Index(thread, "[") + 1
				threadSpawnLocEndInd := strings.Index(thread, ",")
				threadSpawnLocStr := thread[threadSpawnLocStartInd:threadSpawnLocEndInd]
				threadSpawnLoc := interp(threadSpawnLocStr)
				fmt.Printf("\tThread %q (%q, spawned at [ %q ])\n", tid, threadType, threadSpawnLoc)
			} else {
				fmt.Printf("\tThread %q (%q)\n", tid, threadType)
			}

			if readWrite == "r" {
				accessKind = "read"
			} else {
				accessKind = "write"
			}
			fmt.Printf("\tAccess: %s\n", formatutil.Sanitize(accessKind))

			srcLoc := interp(srcLocStr)
			fmt.Printf("\tAccess location: [ %s ]\n", formatutil.Sanitize(srcLoc))

		}

		printAccess(1, record[0], record[1], record[2], record[3])
		printAccess(2, record[4], record[5], record[6], record[7])

		memLocFunc := record[8]
		memLoc := interp(record[9])
		allocType := record[9][1:]
		if len(memLocFunc) > 0 {
			fmt.Printf("Memory accessed:\n\tallocated in func %s at [ %s ]\n",
				formatutil.Sanitize(memLocFunc), formatutil.Sanitize(memLoc))
		} else {
			fmt.Printf("Memory accessed:\n\t%s (global)\n", allocType)
		}

		fmt.Println("=============")
	}
}

//gocyclo:ignore
func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprint(os.Stderr, "Error: no package given, exiting..\n")
		flag.Usage()
		os.Exit(1)
	}

	// Create the output directory if it does not exist
	err := os.MkdirAll(outputPath, 0750) // folder permissions: drwxr-x--- (other users can't write)
	if err != nil {
		log.Fatal(err)
	}

	prog, ssaPkgs, err := createSSA(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	// For easier debugging, we currently only analyze the source code
	// inside packages we care about, but not the source of library functions.
	relevantPkgs := make(map[*ssa.Package]bool)
	for _, p := range ssaPkgs {
		relevantPkgs[p] = true
		members := p.Members
		for _, member := range members {
			switch member.(type) {
			case *ssa.Global:
				name := p.Pkg.Name() + "@" + member.Name()
				typeStr, typeKind, elemType := printType(member.Type().Underlying())
				printFact("Global", name, typeStr, typeKind, elemType)
			case *ssa.Type:
				t := member.Type().Underlying()
				switch typeObj := t.(type) {
				case *types.Struct:
					numFields := typeObj.NumFields()
					for i := 0; i < numFields; i++ {
						field := typeObj.Field(i)
						typeStr, typeKind, elemType := printType(field.Type())
						printFact("StructFields", member.Type().String(), i, typeStr, typeKind, elemType)
					}
				}
			}
		}
	}

	now := time.Now()
	stamp := fmt.Sprintf("_%d-%d-%d_%d:%d:%d_id%d_",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), rand.Int())
	// Generate facts for Soufflé Datalog
	factsFile, err := os.Create(factGenerationLogName(stamp))
	if err != nil {
		log.Fatal(err)
	}
	defer factsFile.Close()

	ssaFile, err2 := os.Create(ssaOutputFileName(stamp))
	if err2 != nil {
		log.Fatal(err2)
	}
	defer ssaFile.Close()

	allFunctions := ssautil.AllFunctions(prog)

	// Fix the ordering of functions to be analyzed to facilitate debugging.
	findFunctionByName := make(map[string]*ssa.Function)
	functionNames := make([]string, 0, len(allFunctions))
	for f := range allFunctions {
		if relevantPkgs[f.Pkg] {
			fName := f.String()
			functionNames = append(functionNames, fName)
			findFunctionByName[fName] = f
		}
	}

	sort.Strings(functionNames)

	// Print facts about each function that we care about.
	for _, fName := range functionNames {
		log.Println("processing relevant function:", fName)
		funcPtr := findFunctionByName[fName]
		processFunction(factsFile, ssaFile, funcPtr)
	}

	// Copy the analysis root file to the output folder
	rootsFile, err := os.Open(rootFunctionsFilePath) //open the source file
	if err != nil {
		log.Fatal(err)
	}
	rootsOutputPath := filepath.Join(outputPath, "_AnalysisRoots.facts")
	destinationFile, err := os.Create(rootsOutputPath) //create the destination file
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(destinationFile, rootsFile) //copy the contents of source to destination file
	if err != nil {
		log.Fatal(err)
	}
	rootsFile.Close()
	destinationFile.Close()

	// Compute a call graph using CHA that acts as a basis for the context-sensitive
	// pointer analysis in Datalog
	cg := cha.CallGraph(prog)
	callgraph.GraphVisitEdges(cg, func(edge *callgraph.Edge) error {
		callerName := getFuncName(edge.Caller.Func)
		calleeName := getFuncName(edge.Callee.Func)
		if edge.Callee.Func.Name() == "init" {
			return nil
		}
		cc := edge.Site.Common()
		callSite := ssaLocForCallInst[cc]
		isGo := callInstIsGo[cc]
		printFact("ChaCallGraph", callSite, callerName, calleeName, isGo)
		return nil
	})

	// Print debugging information to stdout
	log.Println("Facts debug log:", factGenerationLogName(stamp))
	log.Println("SSA:", ssaOutputFileName(stamp))

	// Print the facts that Souffle might read, even though it might be populated for the
	// source program that is being analyzed. Souffle errs on non-existing fact files.
	printEmptyFacts()

	// Close all the fact file writers.
	for _, w := range factWriters {
		w.Close()
	}

	// Invoke the souffle executable on the analysis using the generated facts.
	runSouffle()

	// Read the souffle output from disk and print the results.
	parseSouffleOutput(stamp, prog)

}
