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

package specs

import (
	"github.com/awslabs/ar-go-tools/analysis/scanning"
	"github.com/awslabs/ar-go-tools/internal/funcutil"
	"github.com/awslabs/ar-go-tools/internal/pointer"
)

func matchSsaCodeAnySpec(
	p *pointer.Result,
	codeSpecs []scanning.CodeSpec,
	ssaCode scanning.SsaCode,
) bool {
	return funcutil.Exists(codeSpecs, func(c scanning.CodeSpec) bool {
		return c.MatchSsaCode(p, ssaCode)
	})
}

func compileCids(cids []ParsedCodeIdentifier, forceArg bool) ([]scanning.CodeSpec, error) {
	codeSpecs := []scanning.CodeSpec{}
	for _, cid := range cids {
		codeSpec, err := cid.CompileForceArg(forceArg)
		if err != nil {
			return nil, err
		}
		codeSpecs = append(codeSpecs, codeSpec)
	}
	return codeSpecs, nil
}
