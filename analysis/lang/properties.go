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

package lang

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

// IsChannelEnclosingType return true if the type is a pointer to channel, a channel, or a data structure containing
// a channel
func IsChannelEnclosingType(t types.Type) bool {
	visitedTypes := map[types.Type]bool{}
	toVisit := []types.Type{t}
	addNext := func(t types.Type) {
		if !visitedTypes[t] {
			toVisit = append(toVisit, t)
		}
	}
	for len(toVisit) > 0 {
		head := toVisit[0]
		toVisit = toVisit[1:]
		visitedTypes[head] = true
		switch typ := head.Underlying().(type) {
		case *types.Chan:
			return true
		case *types.Pointer:
			addNext(typ.Elem())
		case *types.Slice:
			addNext(typ.Elem())
		case *types.Map:
			addNext(typ.Elem())
		case *types.Array:
			addNext(typ.Elem())
		case *types.Tuple:
			n := typ.Len()
			for i := 0; i < n; i++ {
				addNext(typ.At(i).Type())
			}
		case *types.Struct:
			n := typ.NumFields()
			for i := 0; i < n; i++ {
				addNext(typ.Field(i).Type())
			}

		}
	}
	return false
}

func IsPredicateFunctionType(f *types.Signature) bool {
	if f.Results().Len() != 1 {
		return false
	}
	resType := f.Results().At(0)
	if resType.Type().Underlying().String() == "bool" {
		return true
	}
	return false
}
