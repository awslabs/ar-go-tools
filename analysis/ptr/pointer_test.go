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

package ptr_test

import (
	"embed"
	"path/filepath"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

//go:embed testdata
var testfsys embed.FS

func TestPointer(t *testing.T) {
	t.Parallel()
	type args struct {
		dirName     string
		extraFiles  []string
		expectError func(error) bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ptr-no-panic-tests",
			args: args{"ptr-no-panic-tests", []string{}, noErrorExpected},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runTest(t, tt.args.dirName, tt.args.extraFiles, tt.args.expectError)
		})
	}
}

func runTest(t *testing.T, dirName string, files []string, errorExpected func(e error) bool) {
	dirName = filepath.Join("./testdata", dirName)
	lp := analysistest.LoadTest(testfsys, dirName, files, analysistest.LoadTestOptions{ApplyRewrite: false})
	if lp.IsErr() {
		t.Fatalf("failed to load test: %v", lp)
	}
	result.Do(lp, func(lp *loadprogram.State) { setupConfig(lp) })
	ptrState, err := result.Bind(lp, ptr.NewState).Value()
	if err != nil {
		if !errorExpected(err) {
			t.Errorf("pointer analysis returned error: %v", err)
		}
		return
	}

	// Verify pointer analysis completed successfully
	if ptrState.PointerAnalysis == nil {
		t.Error("pointer analysis result is nil")
	}
}

func setupConfig(lp *loadprogram.State) {
	cfg := lp.Config
	cfg.Options.ReportCoverage = false
	cfg.Options.ReportPaths = false
	cfg.Options.ReportSummaries = false
	cfg.Options.ReportsDir = ""
	cfg.LogLevel = int(config.ErrLevel)

	lp.Logger = config.NewLogGroup(cfg)
}

func noErrorExpected(_ error) bool {
	return false
}
