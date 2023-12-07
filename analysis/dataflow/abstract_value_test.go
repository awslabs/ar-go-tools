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

import "testing"

func Test_pathMatchField(t *testing.T) {
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
			got, got1 := pathMatchField(tt.args.path, tt.args.fieldName)
			if got != tt.want {
				t.Errorf("pathMatchField() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("pathMatchField() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_pathMatchIndex(t *testing.T) {
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
			got, got1 := pathMatchIndex(tt.args.path)
			if got != tt.want {
				t.Errorf("pathMatchIndex() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("pathMatchIndex() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
