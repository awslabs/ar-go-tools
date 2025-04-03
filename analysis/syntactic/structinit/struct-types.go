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

package structinit

import (
	"fmt"
	"go/types"

	"github.com/awslabs/ar-go-tools/analysis/config"
)

// structType contains both the named struct type
// (e.g., "<pkg-path>/structinit.structType") and its
// underlying struct type (e.g. "struct { strct: [...] }").
//
// named can be nil if the struct does not have a named type
// (i.e., it is anonymous).
type structType struct {
	strct   *types.Struct
	named   *types.Named
	isPtr   bool
	isField bool
}

func (t structType) String() string {
	name := "<anon>"
	if t.named != nil {
		name = t.named.String()
	}
	ptr := ""
	if t.isPtr {
		ptr = "ptr to "
	}
	return fmt.Sprintf("%s%s %s (field? %v)", ptr, name, t.strct.String(), t.isField)
}

// isStructType returns the structType of t and true if t is a struct type, otherwise false.
func isStructType(t types.Type) (structType, bool) {
	return isStructTypeHelper(t, false)
}

// isStructFieldType returns the structType of struct field type t and true if t is a struct type,
// otherwise false.
func isStructFieldType(t types.Type) (structType, bool) {
	return isStructTypeHelper(t, true)
}

func isStructTypeHelper(t types.Type, isField bool) (structType, bool) {
	if t == nil {
		return structType{}, false
	}
	if t.Underlying() == nil {
		return structType{}, false
	}

	typ := t
	isPtr := false
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
		isPtr = true
	}

	if n, ok := typ.(*types.Named); ok {
		if s, ok := n.Underlying().(*types.Struct); ok {
			return structType{strct: s, named: n, isPtr: isPtr, isField: isField}, true
		}
	}

	if s, ok := typ.(*types.Struct); ok {
		return structType{strct: s, named: nil, isPtr: isPtr, isField: isField}, true
	}

	return structType{}, false
}

// structTypesThatMatchSpec returns all the struct types in t (transitive: fields can be struct
// types too) that match the struct specified in spec.
func structTypesThatMatchSpec(spec config.StructInitSpec, t types.Type) []structType {
	var res []structType
	typs := allStructTypes(t)
	if len(typs) == 0 {
		return nil
	}

	for _, typ := range typs {
		if !spec.Struct.MatchType(typ.named) {
			continue
		}

		res = append(res, typ)
	}

	return res
}

// allStructTypes returns the all the named and underlying types of t if it is a struct or pointer to a
// struct.
// It returns nil if t is not a struct type.
//
// A struct can have multiple struct types within it (e.g., a struct containing a field that
// itself is a struct) so the function returns multiple struct types.
func allStructTypes(t types.Type) []structType {
	return allStructTypesHelper(t, nil, false)
}

func allStructTypesHelper(t types.Type, typs []*types.Struct, isField bool) []structType {
	var res []structType
	st, ok := isStructTypeHelper(t, isField)
	if !ok {
		return nil
	}
	// Avoid infinite recursion: don't recurse if the struct type has already been seen
	for _, seen := range typs {
		if types.Identical(st.strct, seen) {
			return nil
		}
	}
	typs = append(typs, st.strct)

	res = append(res, st)
	for i := 0; i < st.strct.NumFields(); i++ {
		fieldTyps := allStructTypesHelper(st.strct.Field(i).Type(), typs, true) // recursive call
		res = append(res, fieldTyps...)
	}

	return res
}
