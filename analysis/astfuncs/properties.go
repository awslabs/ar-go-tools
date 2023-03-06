package astfuncs

import (
	"go/types"
)

// IsNillableType returns true if t is a type that can have the nil value.
func IsNillableType(t types.Type) bool {
	switch t.(type) {
	case *types.Pointer, *types.Interface, *types.Slice, *types.Map, *types.Chan:
		return true
	case *types.Named:
		return IsNillableType(t.Underlying())
	case *types.Signature:
		return true
	default:
		return false
	}
}
