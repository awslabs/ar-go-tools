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

package analysis_test

import (
	"fmt"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/internal/analysistest"
	"golang.org/x/tools/go/ssa"
)

func TestLoadCore(t *testing.T) {
	files := []string{"core/agent.go", "core/agent_unix.go", "core/agent_parser.go"}
	testLoadAgent(t, files)
}

func TestLoadAgentWorker(t *testing.T) {
	files := []string{"agent/agent.go", "agent/agent_parser.go", "agent/agent_unix.go"}
	testLoadAgent(t, files)
}

func TestDocumentWorker(t *testing.T) {
	files := []string{"agent/framework/processor/executer/outofproc/worker/main.go"}
	testLoadAgent(t, files)
}

func TestSessionWorker(t *testing.T) {
	files := []string{"agent/framework/processor/executer/outofproc/sessionworker/main.go"}
	testLoadAgent(t, files)
}

func TestLoadUpdater(t *testing.T) {
	files := []string{"agent/update/updater/updater.go", "agent/update/updater/updater_unix.go"}
	testLoadAgent(t, files)
}

func TestLoadCli(t *testing.T) {
	files := []string{"agent/cli-main/cli-main.go"}
	testLoadAgent(t, files)
}

func TestSessionLogger(t *testing.T) {
	files := []string{"agent/session/logging/main.go"}
	testLoadAgent(t, files)
}

func TestDirectives(t *testing.T) {
	tests := []struct {
		kind analysis.DirectiveKind
		want map[token.Position]analysis.DirectiveKind
	}{
		{kind: analysis.DirectiveIgnore, want: make(map[token.Position]analysis.DirectiveKind)},
	}

	for _, tc := range tests {
		// Change directory to the testdata folder to be able to load packages
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Join(filepath.Dir(filename), "..", "testdata", "src", "directives", string(tc.kind))
		if err := os.Chdir(dir); err != nil {
			panic(err)
		}

		lp := analysistest.LoadTest(t, ".", []string{})
		got := lp.Directives
		if len(got) == 0 {
			t.Fatal("no directives")
		}
		for _, d := range got {
			t.Logf("%+v\n", d)
		}
	}

}

// testLoadAgent loads the agent and logs the packages.
func testLoadAgent(t *testing.T, files []string) {
	const agentPath = "../amazon-ssm-agent/"
	lp, err := loadProgram(agentPath, files)
	if err != nil {
		// We don't expect the agent to be in the pipeline, so don't fail here
		t.Logf("failed to load agent program: %v", err)
	}

	logPkgs(t, lp)
}

func loadProgram(dirRelPath string, files []string) (analysis.LoadedProgram, error) {
	_, curFile, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(curFile), dirRelPath)
	err := os.Chdir(dir)
	if err != nil {
		return analysis.LoadedProgram{}, fmt.Errorf("failed to load directory %s: %v", dir, err)
	}

	lp, err := analysis.LoadProgram(nil, "", ssa.BuilderMode(0), files)
	if err != nil {
		return analysis.LoadedProgram{}, fmt.Errorf("failed to load program: %v", err)
	}

	return lp, nil
}

func logPkgs(t *testing.T, lp analysis.LoadedProgram) {
	for _, pkg := range lp.Packages {
		t.Logf("loaded package: %s\n", pkg)
	}
}
