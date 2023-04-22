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

package dataflow_test

import (
	"fmt"
	"log"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/argot/analysis/dataflow"
	"github.com/awslabs/argot/analysis/testutils"
)

func TestComputeCtxts(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/dataflow/callctx")
	program, config := testutils.LoadTest(t, dir, []string{})
	cache, err := dataflow.BuildFullCache(log.Default(), config, program)
	if err != nil {
		t.Fatalf("error building cache: %s", err)
	}
	ci, err := dataflow.ComputeCtxts(cache, 5)
	if err != nil {
		t.Fatalf("error computing contexts: %s", err)
	}
	if !ci.Contexts["0"] {
		t.Fatalf("did not start at root")
	}
	if !ci.Contexts["0.1"] {
		t.Fatalf("no call from root to init")
	}
	if !ci.Contexts["0.1.2"] {
		t.Fatalf("no call from main to 2")
	}
	for ctx := range ci.Contexts {
		if strings.HasPrefix(ctx, "0") {
			fmt.Printf("%s\n", ctx)
			for _, node := range ci.KeyToNodes(ctx) {
				if node != nil {
					fmt.Printf("\t%s", node.Func.Name())
				}
			}
			fmt.Println()

		}
	}
}
