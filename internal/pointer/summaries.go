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

package pointer

import "golang.org/x/tools/go/ssa"

// findSummary returns a non-nil constraintGenerator when the function has been summarized by the user.
// Currently, the only user-definable summaries are through the list of no-effect function of the config.
func (a *analysis) findSummary(fn *ssa.Function) constraintGenerator {
	impl, ok := a.summarized[fn]
	if !ok {
		if a.config.NoEffectFunctions[fn.String()] {
			impl = ext۰NoEffect
		} else {
			return nil
		}
		a.intrinsics[fn] = impl
	}
	return impl
}
