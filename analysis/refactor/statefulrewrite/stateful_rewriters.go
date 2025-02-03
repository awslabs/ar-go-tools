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

package statefulrewrite

import (
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/funcutil/result"
)

// StatefulRewritesOverlayTransform transforms the overlay in the config state by building
// the program, computing the necessary stateful rewrites, and setting the overlay in the
// config state with the appropriate rewritten files.
func StatefulRewritesOverlayTransform(c *config.State) result.Result[config.State] {
	newOverlayElements := map[string][]byte{}

	// Build a pointer state
	state, err := result.Bind(loadprogram.NewState(c), ptr.NewState).Value()
	cfg := findReflectValueCallToRewrite(state)
	if cfg.IsNone() {
		return result.Ok(c)
	}
	RewriteCallsToReflectValueCall(state.Program, state.Packages, cfg.Value())

	if err != nil {
		return result.Err[config.State](err)
	}

	for k, v := range newOverlayElements {
		c.Overlay[k] = v
	}

	return result.Ok(c)
}

func findReflectValueCallToRewrite(state *ptr.State) funcutil.Optional[ReflectValueCallRewriterSpec] {
	return funcutil.None[ReflectValueCallRewriterSpec]()
}
