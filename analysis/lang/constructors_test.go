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
	"go/token"
	"testing"

	"github.com/dave/dst"
)

func TestExpr(t *testing.T) {
	a := dst.NewIdent("a")
	b := dst.NewIdent("b")
	aPlusB := NewBinOp(token.ADD, a, b)
	minusAplusB := NewUnOp(token.SUB, aPlusB)
	t.Logf("[-(a+b)] -> %s", minusAplusB) // TODO: write or find a function to print single expressions
}
