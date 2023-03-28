package ssafuncs

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// A ValueOp contains the methods necessary to implement an exhaustive switch on ssa.Value
type ValueOp interface {
	DoFunction(*ssa.Function)
	DoFreeVar(*ssa.FreeVar)
	DoParameter(*ssa.Parameter)
	DoConst(*ssa.Const)
	DoGlobal(*ssa.Global)
	DoBuiltin(*ssa.Builtin)
	DoAlloc(*ssa.Alloc)
	DoPhi(*ssa.Phi)
	DoCall(*ssa.Call)
	DoBinOp(*ssa.BinOp)
	DoUnOp(*ssa.UnOp)
	DoChangeType(*ssa.ChangeType)
	DoSliceToArrayPointer(*ssa.SliceToArrayPointer)
	DoMakeInterface(*ssa.MakeInterface)
	DoMakeClosure(*ssa.MakeClosure)
	DoMakeMap(*ssa.MakeMap)
	DoMakeChan(*ssa.MakeChan)
	DoMakeSlice(*ssa.MakeSlice)
	DoSlice(*ssa.Slice)
	DoFieldAddr(*ssa.FieldAddr)
	DoField(*ssa.Field)
	DoIndexAddr(*ssa.IndexAddr)
	DoIndex(*ssa.Index)
	DoLookup(*ssa.Lookup)
	DoSelect(*ssa.Select)
	DoRange(*ssa.Range)
	DoNext(*ssa.Next)
	DoTypeAssert(*ssa.TypeAssert)
	DoExtract(*ssa.Extract)
}

// ValueSwitch implements a simple switch on ssa.Value that applies the correct function from the ValueOp in each case.
func ValueSwitch(vmap ValueOp, v *ssa.Value) {
	switch val := (*v).(type) {
	case *ssa.Function:
		vmap.DoFunction(val)
	case *ssa.FreeVar:
		vmap.DoFreeVar(val)
	case *ssa.Parameter:
		vmap.DoParameter(val)
	case *ssa.Const:
		vmap.DoConst(val)
	case *ssa.Global:
		vmap.DoGlobal(val)
	case *ssa.Builtin:
		vmap.DoBuiltin(val)
	case *ssa.Alloc:
		vmap.DoAlloc(val)
	case *ssa.Phi:
		vmap.DoPhi(val)
	case *ssa.Call:
		vmap.DoCall(val)
	case *ssa.BinOp:
		vmap.DoBinOp(val)
	case *ssa.UnOp:
		vmap.DoUnOp(val)
	case *ssa.ChangeType:
		vmap.DoChangeType(val)
	case *ssa.SliceToArrayPointer:
		vmap.DoSliceToArrayPointer(val)
	case *ssa.MakeInterface:
		vmap.DoMakeInterface(val)
	case *ssa.MakeClosure:
		vmap.DoMakeClosure(val)
	case *ssa.MakeMap:
		vmap.DoMakeMap(val)
	case *ssa.MakeChan:
		vmap.DoMakeChan(val)
	case *ssa.MakeSlice:
		vmap.DoMakeSlice(val)
	case *ssa.Slice:
		vmap.DoSlice(val)
	case *ssa.FieldAddr:
		vmap.DoFieldAddr(val)
	case *ssa.Field:
		vmap.DoField(val)
	case *ssa.IndexAddr:
		vmap.DoIndexAddr(val)
	case *ssa.Index:
		vmap.DoIndex(val)
	case *ssa.Lookup:
		vmap.DoLookup(val)
	case *ssa.Select:
		vmap.DoSelect(val)
	case *ssa.Range:
		vmap.DoRange(val)
	case *ssa.Next:
		vmap.DoNext(val)
	case *ssa.TypeAssert:
		vmap.DoTypeAssert(val)
	case *ssa.Extract:
		vmap.DoExtract(val)
	}
}

// ValuesWithSameData
// TODO this function is incomplete
func ValuesWithSameData(v ssa.Value) map[ssa.Value]bool {
	valueSet := map[ssa.Value]bool{v: true}
	for _, instr := range *(v.Referrers()) {
		switch sameData := instr.(type) {
		case *ssa.MakeInterface:
			if sameData.X == v { // this should always be true
				valueSet[instr.(ssa.Value)] = true // conversion will always succeed
			}
		case *ssa.UnOp:
			if ok, vStruct := MatchLoadField(sameData); ok {
				valueSet[vStruct] = true
			}

			// the default case is to not add the value to the map of values with same data as v
		}
	}
	switch val := v.(type) {
	case *ssa.MakeInterface:
		valueSet[val.X] = true // interface cast refers to same data
	}
	return valueSet
}

// MatchLoadField matches instruction sequence:
// y = &z.Field
// z = *y
// and returns (true, z) if x is given as argument
func MatchLoadField(x ssa.Value) (bool, ssa.Value) {
	if x == nil {
		return false, nil
	}
	loadInstr, ok := x.(*ssa.UnOp)
	if !ok || loadInstr.Op != token.MUL {
		return false, nil
	}
	field, ok := loadInstr.X.(*ssa.FieldAddr)
	if !ok {
		return false, nil
	}
	return true, field.X
}
