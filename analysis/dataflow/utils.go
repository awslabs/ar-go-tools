package dataflow

import (
	"fmt"
	"go/types"

	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/config"
	. "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/ssafuncs"
	"golang.org/x/tools/go/ssa"
)

type functionToNode map[*ssa.Function][]ssa.Node

type PackageToNodes map[*ssa.Package]functionToNode

type nodeIdFunction func(*config.Config, ssa.Node) bool

func NewPackagesMap(c *config.Config, pkgs []*ssa.Package, f nodeIdFunction) PackageToNodes {
	packageMap := make(PackageToNodes)
	for _, pkg := range pkgs {
		pkgMap := newPackageMap(c, pkg, f)
		if len(pkgMap) > 0 {
			packageMap[pkg] = pkgMap
		}
	}
	return packageMap
}

func newPackageMap(c *config.Config, pkg *ssa.Package, f nodeIdFunction) functionToNode {
	fMap := make(functionToNode)
	for _, mem := range pkg.Members {
		switch fn := mem.(type) {
		case *ssa.Function:
			populateFunctionMap(c, fMap, fn, f)
		}
	}
	return fMap
}

func populateFunctionMap(config *config.Config, fMap functionToNode, current *ssa.Function, f nodeIdFunction) {
	var sources []ssa.Node
	for _, b := range current.Blocks {
		for _, instr := range b.Instrs {
			// An instruction should always be a Node too.
			if n := instr.(ssa.Node); f(config, n) {
				sources = append(sources, n)
			}
		}
	}
	fMap[current] = sources
}

func FindSafeCalleePkg(n *ssa.CallCommon) Optional[string] {
	if n == nil || n.StaticCallee() == nil || n.StaticCallee().Pkg == nil {
		return None[string]()
	}
	return Some(n.StaticCallee().Pkg.Pkg.Name())
}

// FindTypePackage finds the package declaring t or returns an error
// Returns a package name and the name of the type declared in that package
func FindTypePackage(t types.Type) (string, string, error) {
	switch typ := t.(type) {
	case *types.Pointer:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Named:
		// Return package name, type name
		obj := typ.Obj()
		if obj != nil {
			pkg := obj.Pkg()
			if pkg != nil {
				return pkg.Name(), obj.Name(), nil
			} else {
				// obj is in Universe
				return "", obj.Name(), nil
			}

		} else {
			return "", "", fmt.Errorf("could not get name")
		}

	case *types.Array:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Map:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Slice:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Chan:
		return FindTypePackage(typ.Elem()) // recursive call
	case *types.Basic, *types.Tuple, *types.Interface, *types.Signature:
		// We ignore this for now (tuple may involve multiple packages)
		return "", "", fmt.Errorf("not a type with a package and name")
	case *types.Struct:
		// Anonymous structs
		return "", "", fmt.Errorf("%s: not a type with a package and name", typ)
	default:
		// We should never reach this!
		fmt.Printf("unexpected type received: %T %v; please report this issue\n", typ, typ)
		return "", "", nil
	}
}

// FieldAddrFieldName finds the name of a field access in ssa.FieldAddr
// if it cannot find a proper field name, returns "?"
func FieldAddrFieldName(fieldAddr *ssa.FieldAddr) string {
	return getFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

// FieldFieldName finds the name of a field access in ssa.Field
// if it cannot find a proper field name, returns "?"
func FieldFieldName(fieldAddr *ssa.Field) string {
	return getFieldNameFromType(fieldAddr.X.Type().Underlying(), fieldAddr.Field)
}

func getFieldNameFromType(t types.Type, i int) string {
	switch typ := t.(type) {
	case *types.Pointer:
		return getFieldNameFromType(typ.Elem().Underlying(), i) // recursive call
	case *types.Struct:
		// Get the field name given its index
		fieldName := "?"
		if 0 <= i && i < typ.NumFields() {
			fieldName = typ.Field(i).Name()
		}
		return fieldName
	default:
		return "?"
	}
}

// IntraProceduralPathExists returns true iff there is a path between the begin and end instructions in a single
// function body.
func IntraProceduralPathExists(begin ssa.Instruction, end ssa.Instruction) bool {
	return FindIntraProceduralPath(begin, end) != nil
}

// FindIntraProceduralPath returns a path between the begin and end instructions.
// Returns nil if there is no path between being and end inside the function.
func FindIntraProceduralPath(begin ssa.Instruction, end ssa.Instruction) []ssa.Instruction {
	// Return nil if the parent functions of being and end are different
	if begin.Parent() != end.Parent() {
		return nil
	}

	if begin.Block() != end.Block() {
		blockPath := FindPathBetweenBlocks(begin.Block(), end.Block())
		if blockPath == nil {
			return nil
		} else {
			var path []ssa.Instruction

			path = append(path, InstructionsBetween(begin.Block(), begin, ssafuncs.LastInstr(begin.Block()))...)
			for _, block := range blockPath[1 : len(blockPath)-1] {
				path = append(path, block.Instrs...)
			}
			path = append(path, InstructionsBetween(end.Block(), ssafuncs.FirstInstr(end.Block()), end)...)
			return path
		}
	} else {
		return InstructionsBetween(begin.Block(), begin, end)
	}
}

// InstructionsBetween returns the instructions between begin and end in the block.
// If begin and end are not two instructions that appear in the same block and being appears before end, then
// the function returns nil.
func InstructionsBetween(block *ssa.BasicBlock, begin ssa.Instruction, end ssa.Instruction) []ssa.Instruction {
	flag := false
	var path []ssa.Instruction
	for _, instr := range block.Instrs {
		if instr == begin {
			flag = true
		}
		if flag {
			path = append(path, instr) // type cast cannot fail
		}
		if flag && instr == end {
			return path
		}
	}
	return nil
}

// FindPathBetweenBlocks is a BFS of the blocks successor graph returns a list of block indexes representing a path
// from begin to end. Returns nil iff there is no such path.
func FindPathBetweenBlocks(begin *ssa.BasicBlock, end *ssa.BasicBlock) []*ssa.BasicBlock {
	visited := make(map[*ssa.BasicBlock]int)
	t := &ssafuncs.BlockTree{Block: begin, Parent: nil, Children: []*ssafuncs.BlockTree{}}
	queue := []*ssafuncs.BlockTree{t}
	// BFS - optimize?
	for {
		if len(queue) == 0 {
			return nil
		} else {
			cur := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			visited[cur.Block] = 1
			if cur.Block == end {
				return cur.PathToLeaf().ToBlocks()
			}
			for _, block := range cur.Block.Succs {
				if _, ok := visited[block]; !ok {
					child := cur.AddChild(block)
					queue = append(queue, child)
				}
			}
		}
	}
}

// containsCallNode returns true if nodes contains node, otherwise false
func containsCallNode(nodes []*CallNode, node *CallNode) bool {
	// The number of nodes in a call is expected to be small
	for _, x := range nodes {
		if x.Callee() == node.Callee() {
			return true
		}
	}
	return false
}

// MapContainsCallNode returns true if nodes contains node, otherwise false
func MapContainsCallNode(nodes map[ssa.CallInstruction]*CallNode, node *CallNode) bool {
	// The number of nodes in a call is expected to be small
	for _, x := range nodes {
		if x.callee == node.callee {
			return true
		}
	}
	return false
}
