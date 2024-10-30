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

package config

import (
	"fmt"

	"github.com/awslabs/ar-go-tools/internal/funcutil"
)

// Validate validates the config and returns an error if there is some invalid setting
func (c Config) Validate() error {
	if err := c.checkTagsAreUnique(); err != nil {
		return err
	}
	return nil
}

func (c Config) checkTagsAreUnique() error {
	hasUnsetTag := false
	tags := map[string]bool{}
	tagsList := funcutil.Map(c.TaintTrackingProblems, func(ts TaintSpec) string { return ts.Tag })
	tagsList = append(tagsList, funcutil.Map(c.SlicingProblems, func(ts SlicingSpec) string { return ts.Tag })...)
	for _, tag := range tagsList {
		if tag == "" {
			if hasUnsetTag {
				return fmt.Errorf("there can be only one problem with an unspecified tag")
			}
			hasUnsetTag = true
		} else if tags[tag] {
			return fmt.Errorf("tag %s is used for multiple problems", tag)
		}
		tags[tag] = true
	}
	return nil
}
