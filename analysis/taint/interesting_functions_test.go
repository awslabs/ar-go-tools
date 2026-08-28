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

package taint_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/analysis/taint"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

// findSignalsFor returns the signals recorded for the function named name, or nil if none.
func findSignalsFor(interesting taint.InterestingFunctions, name string) *taint.InterestingFunctionSignals {
	for f, sig := range interesting {
		if f.Name() == name {
			return sig
		}
	}
	return nil
}

func TestInterestingFunctionsRecursion(t *testing.T) {
	t.Parallel()
	res := runTestWithoutCheck(t, "interesting-functions", nil, false, noErrorExpected)

	sig := findSignalsFor(res.res.InterestingFunctions, "recursive2")
	if sig == nil || !sig.IsRecursive {
		t.Errorf("expected recursive2 to be recorded as recursive, got %+v", sig)
	}
}

func TestInterestingFunctionsConcurrency(t *testing.T) {
	t.Parallel()
	res := runTestWithoutCheck(t, "interesting-functions", nil, false, noErrorExpected)

	sig := findSignalsFor(res.res.InterestingFunctions, "concurrent")
	if sig == nil {
		t.Fatal("expected signals to be recorded for concurrent")
	}
	found := false
	for _, u := range sig.Unsoundness {
		if u == taint.UnsoundnessConcurrency {
			found = true
		}
	}
	if !found {
		t.Errorf("expected concurrent to be recorded with UnsoundnessConcurrency, got %+v", sig.Unsoundness)
	}
}

func TestInterestingFunctionsInterfaceFanout(t *testing.T) {
	t.Parallel()
	res := runTestWithoutCheck(t, "interesting-functions", nil, false, noErrorExpected)

	sig := findSignalsFor(res.res.InterestingFunctions, "F")
	if sig == nil || len(sig.InterfaceFanouts) == 0 {
		t.Fatalf("expected an interface-dispatched impl's F to be recorded with fanout, got %+v", sig)
	}
	// F's call site is reached via two different calling contexts (testInterfaceFanout and
	// testInterfaceFanoutOtherContext), but the fanout fact itself is identical both times, so it
	// should only be recorded once (see recordInterfaceFanout's deduplication).
	if len(sig.InterfaceFanouts) != 1 {
		t.Errorf("expected exactly 1 InterfaceFanout entry despite 2 calling contexts, got %d: %+v",
			len(sig.InterfaceFanouts), sig.InterfaceFanouts)
	}
	fanout := sig.InterfaceFanouts[0]
	if fanout.NumImpls != 20 {
		t.Errorf("expected 20 implementations, got %d", fanout.NumImpls)
	}
	if fanout.MethodName != "F" {
		t.Errorf("expected method name F, got %s", fanout.MethodName)
	}
}

func TestInterestingFunctionsInterfaceFanoutSubsumption(t *testing.T) {
	t.Parallel()
	res := runTestWithoutCheck(t, "interesting-functions", nil, false, noErrorExpected)

	// impl2.F is dispatched via both Fanout (the more general interface: just F) and WideFanout
	// (Fanout embedded, plus G): WideFanout's method set is a strict superset of Fanout's, so
	// only the Fanout.F entry should be recorded -- WideFanout.F would be a redundant, more
	// specific summary target.
	sig := findSignalsFor(res.res.InterestingFunctions, "F")
	if sig == nil {
		t.Fatal("expected F to have recorded signals")
	}
	for _, fanout := range sig.InterfaceFanouts {
		if fanout.InterfaceName == "WideFanout" {
			t.Errorf("expected WideFanout.F to be subsumed by Fanout.F and not recorded, got %+v",
				sig.InterfaceFanouts)
		}
	}
	foundFanout := false
	for _, fanout := range sig.InterfaceFanouts {
		if fanout.InterfaceName == "Fanout" {
			foundFanout = true
		}
	}
	if !foundFanout {
		t.Errorf("expected Fanout.F to be recorded (the more general interface), got %+v", sig.InterfaceFanouts)
	}
}

func TestInterestingFunctionsMaxDepthExceeded(t *testing.T) {
	t.Parallel()
	dirName := filepath.Join("./testdata", "interesting-functions")
	lp := analysistest.LoadTest(testfsys, dirName, nil, analysistest.LoadTestOptions{ApplyRewrite: false})
	if lp.IsErr() {
		t.Fatalf("failed to load test: %v", lp)
	}
	result.Do(lp, func(lp *loadprogram.State) {
		setupConfig(lp, false)
		// A max depth of 2 is small enough to be exceeded inside the private deepHelper1/2/3
		// chain called from the exported DeepEntry.
		lp.Config.UnsafeMaxDepth = 2
	})
	ptrState := result.Bind(lp, ptr.NewState)
	state, err := result.Bind(ptrState, dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to initialize state: %s", err)
	}
	res, err := taint.Analyze(context.Background(), state, taint.AnalysisReqs{})
	if err != nil {
		t.Fatalf("taint analysis returned error: %v", err)
	}

	hasMaxDepth := func(name string) bool {
		sig := findSignalsFor(res.InterestingFunctions, name)
		if sig == nil {
			return false
		}
		for _, u := range sig.Unsoundness {
			if u == taint.UnsoundnessMaxDepth {
				return true
			}
		}
		return false
	}

	if !hasMaxDepth("DeepEntry") {
		t.Errorf("expected exported DeepEntry to be recorded with UnsoundnessMaxDepth, got %+v",
			findSignalsFor(res.InterestingFunctions, "DeepEntry"))
	}
	for _, private := range []string{"deepHelper1", "deepHelper2", "deepHelper3"} {
		if hasMaxDepth(private) {
			t.Errorf("expected private %s to NOT be recorded with UnsoundnessMaxDepth "+
				"(should be attributed to the nearest exported caller instead)", private)
		}
	}
}

func TestInterestingFunctionsTimeout(t *testing.T) {
	t.Parallel()
	dirName := filepath.Join("./testdata", "interesting-functions")
	lp := analysistest.LoadTest(testfsys, dirName, nil, analysistest.LoadTestOptions{ApplyRewrite: false})
	if lp.IsErr() {
		t.Fatalf("failed to load test: %v", lp)
	}
	result.Do(lp, func(lp *loadprogram.State) {
		setupConfig(lp, true)
		// A 1ms timeout is tiny enough to reliably expire before any on-demand intra-procedural
		// analysis completes, without needing an expensive function to analyze.
		lp.Config.DataflowProblems.IntraTimeoutMs = 1
	})
	ptrState := result.Bind(lp, ptr.NewState)
	state, err := result.Bind(ptrState, dataflow.NewState).Value()
	if err != nil {
		t.Fatalf("failed to initialize state: %s", err)
	}

	// A timeout stops the analysis and returns an error (see onDemandIntraProcedural): the result
	// is incomplete past that point, but the signal for the timed-out function is still recorded.
	res, analyzeErr := taint.Analyze(context.Background(), state, taint.AnalysisReqs{})
	if analyzeErr == nil {
		t.Fatal("expected taint.Analyze to return an error on timeout")
	}

	foundTimeout := false
	for _, sig := range res.InterestingFunctions {
		for _, u := range sig.Unsoundness {
			if u == taint.UnsoundnessTimeout {
				foundTimeout = true
			}
		}
	}
	if !foundTimeout {
		t.Error("expected at least one function to be recorded as timed out with a 1ms intra-timeout")
	}
}
