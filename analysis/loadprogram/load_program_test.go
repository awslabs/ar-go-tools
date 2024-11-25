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

package loadprogram

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"golang.org/x/tools/go/ssa"
)

func TestLoadWithProjectRoot(t *testing.T) {
	configFile := filepath.Join("testdata", "state_load_config.yaml")
	cfg, err := tools.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load config")
	}
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../cmd/argot/")
	err = os.Chdir(dir)
	if err != nil {
		t.Fatalf("could not change to cmd/argot dir: %s", err)
		return
	}
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     false,
		ApplyRewrites: true,
		Platform:      "",
		PackageConfig: nil,
	}
	c := config.NewState(cfg, "", []string{"main.go"}, loadOptions)
	program, err := NewState(c).Value()
	if err != nil || len(program.Packages) == 0 {
		t.Fatalf("no packages loaded")
	}
	if err != nil {
		t.Fatalf("error loading state: %s", err)
	}
}

func programLoadTest(t *testing.T, files []string) {
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../amazon-ssm-agent/")
	err := os.Chdir(dir)
	if err != nil {
		// We don't expect the agent to be in the pipeline, so don't fail here
		t.Logf("could not change to agent dir: %s", err)
		return
	}
	loadOptions := config.LoadOptions{
		BuildMode:     ssa.BuilderMode(0),
		LoadTests:     false,
		ApplyRewrites: true,
		Platform:      "",
		PackageConfig: nil,
	}
	c := config.NewState(config.NewDefault(), "", files, loadOptions)
	state, err := NewState(c).Value()
	if err != nil {
		t.Fatalf("error loading packages: %s", err)
	}
	for _, pkg := range state.Program.AllPackages() {
		t.Logf("%s loaded\n", pkg.String())
	}
}

func TestLoadCore(t *testing.T) {
	files := []string{"core/agent.go", "core/agent_unix.go", "core/agent_parser.go"}
	programLoadTest(t, files)
}

func TestLoadAgentWorker(t *testing.T) {
	files := []string{"agent/agent.go", "agent/agent_parser.go", "agent/agent_unix.go"}
	programLoadTest(t, files)
}

func TestDocumentWorker(t *testing.T) {
	files := []string{"agent/framework/processor/executer/outofproc/worker/main.go"}
	programLoadTest(t, files)
}

func TestSessionWorker(t *testing.T) {
	files := []string{"agent/framework/processor/executer/outofproc/sessionworker/main.go"}
	programLoadTest(t, files)
}

func TestLoadUpdater(t *testing.T) {
	files := []string{"agent/update/updater/updater.go", "agent/update/updater/updater_unix.go"}
	programLoadTest(t, files)
}

func TestLoadCli(t *testing.T) {
	files := []string{"agent/cli-main/cli-main.go"}
	programLoadTest(t, files)
}

func TestSessionLogger(t *testing.T) {
	files := []string{"agent/session/logging/main.go"}
	programLoadTest(t, files)
}
