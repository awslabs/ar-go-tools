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

package analysis

import (
	"fmt"
	"os"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// BuildWholeProgramTarget loads the target specified by the list of files provided. Return an analyzer state that has
// been initialized with the program if successful. The Target of that state will be set to the provided name.
func BuildWholeProgramTarget(
	c *config.State,
	name string,
	patterns []string,
	options loadprogram.Options) (*loadprogram.WholeProgramState, error) {
	if name != "" {
		// If it's a named target, need to change to project root's directory to properly load the target
		err := os.Chdir(c.Config.Root())
		if err != nil {
			return nil, fmt.Errorf("failed to change to root dir: %s", err)
		}
	}
	startLoad := time.Now()
	c.Logger.Infof(formatutil.Faint("Reading sources for target") + " " + name + "\n")
	program, pkgs, err := loadprogram.Do(patterns, options)
	if err != nil {
		return nil, fmt.Errorf("could not load program: %v", err)
	}
	wholeProgramState, err := loadprogram.NewWholeProgramState(c, name, program, pkgs)
	loadDuration := time.Since(startLoad)
	if err != nil {
		return nil, fmt.Errorf("failed to load whole program: %v", err)
	}
	c.Logger.Infof("Loaded whole program state in %3.4f s", loadDuration.Seconds())
	return wholeProgramState, nil
}

// BuildPointerTarget loads the target specified by the list of files provided.
// Builds the program and then runs the pointer analysis to return a PointerState.
func BuildPointerTarget(
	c *config.State,
	name string,
	files []string,
	options loadprogram.Options) (*loadprogram.PointerState, error) {
	wp, err := BuildWholeProgramTarget(c, name, files, options)
	if err != nil {
		return nil, err // context for load target is enough
	}
	return loadprogram.NewPointerState(wp)
}

// BuildDataFlowTarget loads the target specified by the list of files provided, runs the pointer analysis
// and then initializes a dataflow analysis state.
func BuildDataFlowTarget(
	c *config.State,
	name string,
	files []string,
	options loadprogram.Options,
) (*dataflow.State, error) {
	ps, err := BuildPointerTarget(c, name, files, options)
	if err != nil {
		return nil, err // context for load target is enough
	}
	return dataflow.NewState(ps)
}
