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

package dataflow

import (
	"go/types"
	"reflect"
	"testing"
)

func Test_accessPathMatchField(t *testing.T) {
	type args struct {
		path      string
		fieldName string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 bool
	}{
		{
			name:  "empty path, empty field name",
			args:  args{path: "", fieldName: ""},
			want:  "",
			want1: true,
		},
		{
			name:  "empty path, some field name",
			args:  args{path: "", fieldName: "field1"},
			want:  "",
			want1: true,
		},
		{
			name:  "some field path, correct field name",
			args:  args{path: ".field1.field2", fieldName: "field1"},
			want:  ".field2",
			want1: true,
		},
		{
			name:  "some field path, incorrect field name",
			args:  args{path: ".field2.field1", fieldName: "field1"},
			want:  ".field2.field1",
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := accessPathMatchField(tt.args.path, tt.args.fieldName)
			if got != tt.want {
				t.Errorf("accessPathMatchField() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("accessPathMatchField() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_accessPathMatchIndex(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 bool
	}{
		{
			name:  "empty path",
			args:  args{path: ""},
			want:  "",
			want1: true,
		},
		{
			name:  "some indexing",
			args:  args{path: "[*]"},
			want:  "",
			want1: true,
		},
		{
			name:  "some indexing then field",
			args:  args{path: "[*].field1"},
			want:  ".field1",
			want1: true,
		},
		{
			name:  "some field then indexing",
			args:  args{path: ".field[*]"},
			want:  ".field[*]",
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := accessPathMatchIndex(tt.args.path)
			if got != tt.want {
				t.Errorf("accessPathMatchIndex() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("accessPathMatchIndex() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_boundedAccessPathsOfType(t *testing.T) {
	type args struct {
		t types.Type
		n int
	}
	SetMaxAccessPathLength(3)

	tInt := types.Typ[types.Int]
	tBool := types.Typ[types.Bool]
	tString := types.Typ[types.String]
	tMapSI := types.NewMap(tString, tInt)
	tSliceString := types.NewSlice(tString)
	tArrayString := types.NewArray(tString, 10)
	fieldA := types.NewField(0, nil, "A", tString, false)
	fieldB := types.NewField(0, nil, "B", tInt, false)
	tStructAB := types.NewStruct([]*types.Var{fieldA, fieldB}, nil)
	tTypeName := types.NewTypeName(0, nil, "structAB", tStructAB)
	tNamedS := types.NewNamed(tTypeName, tStructAB, []*types.Func{})
	fieldC := types.NewField(0, nil, "C", tNamedS, false)
	fieldD := types.NewField(0, nil, "D", tInt, false)
	fieldE := types.NewField(0, nil, "E", tMapSI, false)
	tStructCDE := types.NewStruct([]*types.Var{fieldC, fieldD, fieldE}, nil)
	fieldX := types.NewField(0, nil, "X", tNamedS, true)
	tStructDXEmbed := types.NewStruct([]*types.Var{fieldD, fieldX}, nil)
	tMapStringToS := types.NewMap(tString, tNamedS)
	tSliceS := types.NewSlice(tNamedS)
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "int",
			args: args{t: tInt, n: 2},
			want: []string{},
		},
		{
			name: "bool",
			args: args{t: tBool, n: 2},
			want: []string{},
		},
		{
			name: "string",
			args: args{t: tString, n: 2},
			want: []string{},
		},
		{
			name: "struct{A:string,B:int}",
			args: args{t: tStructAB, n: 2},
			want: []string{".A", ".B"},
		},
		{
			name: "[]string",
			args: args{t: tSliceString, n: 2},
			want: []string{"[*]"},
		},
		{
			name: "[10]string",
			args: args{t: tArrayString, n: 2},
			want: []string{"[*]"},
		},
		{
			name: "map[string]int",
			args: args{t: tMapSI, n: 2},
			want: []string{"[*]"},
		},
		{
			name: "struct{C:structAB,D:int,E:map[string]int}",
			args: args{t: tStructCDE, n: 2},
			want: []string{".C.A", ".C.B", ".D", ".E[*]"},
		},
		{
			name: "struct{,D:int,X:structABt}",
			args: args{t: tStructDXEmbed, n: 2},
			want: []string{".D", ".A", ".B"}, // embedding is skipped
		},
		{
			name: "map[string]structAB",
			args: args{t: tMapStringToS, n: 2},
			want: []string{"[*].A", "[*].B"},
		},
		{
			name: "[]structAB",
			args: args{t: tSliceS, n: 2},
			want: []string{"[*].A", "[*].B"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedAccessPathsOfType(tt.args.t, tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("boundedAccessPathsOfType() = %v, want %v", got, tt.want)
			}
		})
	}
}
