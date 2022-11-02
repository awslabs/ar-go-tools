// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package maypanic

// "may panic" analysis via transition system

import (
	"bytes"
	_ "embed"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

//go:embed embed/template.cpp
var CTemplate string

func findFunctionCalled(f *ssa.Function, functionMap *map[string]uint) (uint, string) {

	name := f.RelString(nil)

	// find it in the functionMap
	functionIndex, ok := (*functionMap)[name]
	if ok {
		return functionIndex, name
	} else {
		panic("failed to find function " + name + " in functionMap")
	}
}

func mayPanicInstruction(instruction *ssa.Instruction, functionMap *map[string]uint, blockMap []int, buf *bytes.Buffer) {

	indent := func() {
		buf.WriteString("      ")
	}

	// Order here matters -- many instruction types are also values
	switch v := (*instruction).(type) {

	case nil:
		indent()
		buf.WriteString("// nil instruction\n")

	case *ssa.Jump:
		// jump to the sole successor of its owning block
		succs := (*v).Block().Succs
		indent()
		fmt.Fprintf(buf, "state.do_Jump(%d);\n", blockMap[succs[0].Index])

	case *ssa.If:
		// jump to one of the two successors of its parent block,
		// depending on the boolean Cond
		succs := (*v).Block().Succs
		indent()
		fmt.Fprintf(buf, "state.do_If(%d, %d);\n", blockMap[succs[0].Index], blockMap[succs[1].Index])

	case *ssa.Return:
		indent()
		buf.WriteString("state.do_Return();\n")

	case *ssa.RunDefers:
		indent()
		buf.WriteString("state.do_RunDefers();\n")

	case *ssa.Panic:
		indent()
		fmt.Fprintf(buf, "state.do_Panic();\n")

	case *ssa.Call:
		// invoke?
		if v.Call.IsInvoke() {
			indent()
			fmt.Fprintf(buf, "state.next_PC(); // Call IsInvoke\n")
		} else {
			switch value := v.Call.Value.(type) {
			case *ssa.Function:
				indent()
				functionIndex, name := findFunctionCalled(value, functionMap)
				fmt.Fprintf(buf, "state.do_Call(%d); // %s\n", functionIndex, name)

			case *ssa.Builtin:
				builtinName := value.Name()
				switch builtinName {
				case "recover":
					indent()
					fmt.Fprintf(buf, "state.do_Recover();\n")

				default:
					indent()
					fmt.Fprintf(buf, "state.do_Skip(); // Builtin %s\n", builtinName)
				}

			default:
				indent()
				fmt.Fprintf(buf, "state.nondet_Panic(); // unknown Call function: %s\n", v.String())
				indent()
				fmt.Fprintf(buf, "state.next_PC();\n")
			}
		}

	case *ssa.Go:
		// invoke?
		if v.Call.IsInvoke() {
			indent()
			fmt.Fprintf(buf, "state.next_PC(); // Go IsInvoke\n")
		} else {
			switch value := v.Call.Value.(type) {
			case *ssa.Function:
				indent()
				functionIndex, name := findFunctionCalled(value, functionMap)
				fmt.Fprintf(buf, "state.do_Go(%d); // %s\n", functionIndex, name)

			default:
				indent()
				fmt.Fprintf(buf, "state.nondet_Panic(); // unknown Go function: %s\n", v.String())
				indent()
				fmt.Fprintf(buf, "state.next_PC();\n")
			}
		}

	case *ssa.Defer:
		// invoke?
		if v.Call.IsInvoke() {
			indent()
			fmt.Fprintf(buf, "state.next_PC(); // Go IsInvoke\n")
		} else {
			switch value := v.Call.Value.(type) {
			case *ssa.Function:
				indent()
				functionIndex, name := findFunctionCalled(value, functionMap)
				fmt.Fprintf(buf, "state.do_Defer(%d); // %s\n", functionIndex, name)

			case *ssa.MakeClosure:
				switch fn := value.Fn.(type) {
				case *ssa.Function:
					indent()
					functionIndex, name := findFunctionCalled(fn, functionMap)
					fmt.Fprintf(buf, "state.do_Defer(%d); // %s\n", functionIndex, name)

				default:
					indent()
					fmt.Fprintf(buf, "state.nondet_Panic(); // unknown Defer function: %s\n", v.String())
					indent()
					fmt.Fprintf(buf, "state.next_PC();\n")
				}

			default:
				indent()
				fmt.Fprintf(buf, "state.nondet_Panic(); // unknown Defer function: %s\n", v.String())
				indent()
				fmt.Fprintf(buf, "state.next_PC();\n")
			}
		}

	case *ssa.Send:
		indent()
		fmt.Fprintf(buf, "state.do_Send();\n")

	case *ssa.Store:
		indent()
		fmt.Fprintf(buf, "state.do_Store();\n")

	case *ssa.MapUpdate:
		indent()
		fmt.Fprintf(buf, "state.do_MapUpdate();\n")

	case *ssa.DebugRef:
		indent()
		fmt.Fprintf(buf, "state.do_DebugRef();\n")

	case ssa.Value:
		indent()
		fmt.Fprintf(buf, "// Value\n")
		indent()
		fmt.Fprintf(buf, "state.do_Skip();\n")

	default:
		indent()
		buf.WriteString("// unknown ssa.Instruction\n")
		indent()
		fmt.Fprintf(buf, "abort();\n")
	}
}

func makeBlockMap(f *ssa.Function) []int {

	blockMap := make([]int, 0, len(f.Blocks))

	var instructionIndex = 0

	for _, b := range f.Blocks {
		blockMap = append(blockMap, instructionIndex)
		instructionIndex += len(b.Instrs)
	}

	return blockMap
}

func mayPanicFunctionBody(program *ssa.Program, functionIndex int, f *ssa.Function, functionMap *map[string]uint, buf *bytes.Buffer) {

	// empty function?
	if len(f.Blocks) == 0 {
		return
	}

	fmt.Fprintf(buf, "// %s\n", f.RelString(nil))
	fmt.Fprintf(buf, "void trans_%s(statet &state) {\n", ConvertIdentifier(f))

	// we first need a map from block indices to instruction indices
	blockMap := makeBlockMap(f)

	fmt.Fprintf(buf, "  switch(state.frame().instruction_index) {\n")

	var instructionIndex = 0

	for _, b := range f.Blocks {
		fmt.Fprintf(buf, "\n    // block %d", b.Index)
		if b.Comment != "" {
			fmt.Fprintf(buf, " %s", b.Comment)
		}
		for _, instr := range b.Instrs {
			fmt.Fprintf(buf, "\n")
			fmt.Fprintf(buf, "    case %d:\n", instructionIndex)
			mayPanicInstruction(&instr, functionMap, blockMap, buf)
			fmt.Fprintf(buf, "      break;\n")
			instructionIndex++
		}
	}

	fmt.Fprintf(buf, "  }\n")
	fmt.Fprintf(buf, "}\n")
	fmt.Fprintf(buf, "\n")
}

func MayPanicModelChecking(program *ssa.Program, exclude []string, json bool) {

	fmt.Fprintf(os.Stdout, "Building analyzer\n")

	type nameAndFunction struct {
		name string
		f    *ssa.Function
	}

	// Get all the functions
	allFunctions := ssautil.AllFunctions(program)

	// get the (full) names of all functions
	functionNames := make([]nameAndFunction, 0, len(allFunctions)+1)
	for f := range allFunctions {
		functionNames = append(functionNames, nameAndFunction{name: f.RelString(nil), f: f})
	}

	// sort alphabetically by name
	sort.Slice(functionNames, func(i, j int) bool {
		return functionNames[i].name < functionNames[j].name
	})

	// write the transition system into a buffer
	var buf bytes.Buffer

	split := strings.Index(CTemplate, "//<--- INSERT CODE HERE --->")
	if split == 0 {
		fmt.Fprintf(os.Stderr, "Error reading the template file")
		os.Exit(1)
	}
	buf.WriteString(CTemplate[:split]) // copy the embedded .cpp file into a Buffer
	split += len("//<--- INSERT CODE HERE --->")

	// Now initialize the second buffer with the hardcoded model data

	// table of function names
	fmt.Fprintf(&buf, "const char *function_names[] = {\n")
	for _, nameAndFunction := range functionNames {
		fmt.Fprintf(&buf, "  \"%s\",\n", nameAndFunction.name)
	}
	fmt.Fprintf(&buf, "};\n\n")

	// table of function file names
	fmt.Fprintf(&buf, "const char *function_file_names[] = {\n")
	for _, nameAndFunction := range functionNames {
		pos := nameAndFunction.f.Pos()
		position := program.Fset.Position(pos)
		fmt.Fprintf(&buf, "  \"%s\",\n", position.Filename)
	}
	fmt.Fprintf(&buf, "};\n\n")

	// table of line numbers for the instructions
	fmt.Fprintf(&buf, "const unsigned *line_numbers[] = {\n")
	for _, nameAndFunction := range functionNames {
		fmt.Fprintf(&buf, "  (unsigned[]){")
		var first = true
		for _, b := range nameAndFunction.f.Blocks {
			for _, instr := range b.Instrs {
				if first {
					first = false
					fmt.Fprintf(&buf, " ")
				} else {
					fmt.Fprintf(&buf, ", ")
				}
				pos := instr.Pos()
				position := program.Fset.Position(pos)
				fmt.Fprintf(&buf, "%d", position.Line)
			}
		}
		fmt.Fprintf(&buf, " },\n")
	}
	fmt.Fprintf(&buf, "};\n\n")

	// create the functionMap
	functionMap := make(map[string]uint)
	for index, nameAndFunction := range functionNames {
		functionMap[nameAndFunction.name] = uint(index)
	}

	// convert the instructions in the function bodies
	for functionIndex, nameAndFunction := range functionNames {
		mayPanicFunctionBody(program, functionIndex, nameAndFunction.f, &functionMap, &buf)
	}

	buf.WriteString("void trans(statet &state) {\n")

	// panic handler
	buf.WriteString("  if(state.frame().panic_handler())\n")
	buf.WriteString("    return state.handle_panic();\n\n")

	buf.WriteString("  switch(state.frame().function_index) {\n")

	// generate the cases
	for functionIndex, nameAndFunction := range functionNames {
		f := nameAndFunction.f
		// empty function?
		if len(f.Blocks) != 0 {
			fmt.Fprintf(&buf, "\n")
			fmt.Fprintf(&buf, "    case %d: // %s\n", functionIndex, f.RelString(nil))
			fmt.Fprintf(&buf, "      trans_%s(state);\n", ConvertIdentifier(f))
			fmt.Fprintf(&buf, "      break;\n")
		}
	}

	// default for all empty functions
	fmt.Fprintf(&buf, "\n")
	fmt.Fprintf(&buf, "    default: // empty functions\n")
	fmt.Fprintf(&buf, "      state.do_Return();\n")

	buf.WriteString("  }\n")
	buf.WriteString("}\n\n")

	// find the 'main' function to generate initial_states()
	var mainFunctionIndex = -1

	for functionIndex, nameAndFunction := range functionNames {
		if nameAndFunction.name == "command-line-arguments.main" {
			mainFunctionIndex = functionIndex
		}
	}

	if mainFunctionIndex == -1 {
		os.Stdout.WriteString("no main function found\n")
		return
	}

	fmt.Fprintf(&buf, "queuet initial_states()\n")
	fmt.Fprintf(&buf, "{\n")
	fmt.Fprintf(&buf, "  statet initial_state;\n")
	fmt.Fprintf(&buf, "  initial_state.frames.emplace_back(%d);\n", mainFunctionIndex)
	fmt.Fprintf(&buf, "  return { std::move(initial_state) };\n")
	fmt.Fprintf(&buf, "}\n\n")

	buf.WriteString(CTemplate[split+1:])

	analyzer_source_file := "/tmp/gozer-analyzer.cpp"
	analyzer_object_file := "/tmp/gozer-analyzer.o"
	analyzer_executable_file := "/tmp/gozer-analyzer.bin"

	var err error

	err = ioutil.WriteFile(analyzer_source_file, buf.Bytes(), 0666)
	if err != nil {
		os.Stderr.WriteString("failed to write to temporary file\n")
		return
	}

	var cmd *exec.Cmd

	// compile
	cmd = exec.Command("ccache", "g++", "-c", "-std=c++11", analyzer_source_file, "-o", analyzer_object_file)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		os.Stderr.WriteString("failed to run C++ compiler\n")
		return
	}

	// link
	cmd = exec.Command("g++", analyzer_object_file, "-o", analyzer_executable_file)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		os.Stderr.WriteString("failed to run C++ linker\n")
		return
	}

	// run
	cmd = exec.Command(analyzer_executable_file)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		os.Stderr.WriteString("failed to run analyzer executable\n")
		return
	}
}
