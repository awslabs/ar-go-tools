package astfuncs

import (
	"go/types"
)

func IsNillableType(t types.Type) bool {
	switch t.(type) {
	case *types.Pointer, *types.Interface, *types.Array, *types.Slice, *types.Map:
		return true
	case *types.Named:
		return IsNillableType(t.Underlying())
	default:
		return false
	}
}
