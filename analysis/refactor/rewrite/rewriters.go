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

package rewrite

import (
	"github.com/awslabs/ar-go-tools/internal/rewrite"
	"golang.org/x/tools/go/packages"
)

// ApplyRewrites applies a series of rewrite steps to the packages and all its dependencies.
// The rewrites are meant to preserve soundness of the analysis, under the condition that the focus points of the
// analysis are not the entrypoint or endpoints of analyses.
// The rewrites are:
//
// All the rewrites from the base rewrites used in capslock package:
// - calls to [sort.Slice] and [sort.SliceStable] are removed and replaced by calls to the functions used in sorting.
// - calls to (sync.Once).Do are replaced by a call to the method in the sync.Once object.
func ApplyRewrites(packages []*packages.Package) {
	rewrite.ApplyBaseRewrites(packages)
}
