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

package analysiscfg

// ProblemCfg are the options that are specific to an analysis problem.
type ProblemCfg struct {
	// MaxAlarms sets a limit for the number of alarms reported by an analysis.  If MaxAlarms > 0, then at most
	// MaxAlarms will be reported. Otherwise, if MaxAlarms <= 0, it is ignored.
	//
	// This setting does not affect soundness, since event with max-alarms:1, at least one path will be reported if
	// there is some potential alarm-causing result.
	MaxAlarms int `xml:"max-alarms,attr" yaml:"max-alarms" json:"max-alarms"`

	// UnsafeMaxDepth sets a limit for the number of function call depth explored during the analysis.
	// The default is -1, and any value less than 0 is safe: the analysis will be sound and explore call depth
	// without bounds.
	//
	// Setting UnsafeMaxDepth to a limit larger than 0 will yield unsound results, but can be useful to use the tool
	// as a checking mechanism. Limiting the call depth will usually yield fewer false positives.
	UnsafeMaxDepth int `xml:"unsafe-max-depth,attr" yaml:"unsafe-max-depth" json:"unsafe-max-depth"`

	// MaxEntrypointContextSize sets the maximum context (call stack) size used when searching for entry points with context.
	// This only impacts precision of the returned results.
	//
	// If MaxEntrypointContextSize is < 0, it is ignored.
	// If MaxEntrypointContextSize is 0 is specified by the user, the value is ignored, and a default internal value is used.
	// If MaxEntrypointContextSize is > 0, then the limit in the callstack size for the context is used.
	MaxEntrypointContextSize int `xml:"max-entrypoint-context-size,attr" yaml:"max-entrypoint-context-size" json:"max-entrypoint-context-size"`
}

// PointerConfig is the pointer analysis specific configuration.
type PointerConfig struct {
	// UnsafeNoEffectFunctions is a list of function names that produce no constraints in the pointer analysis.
	// Use at your own risk: using this option *may* make the analysis unsound. However, if you are confident
	// that the listed function does not have any effect on aliasing, adding it here may reduce false positives.
	UnsafeNoEffectFunctions []string `yaml:"unsafe-no-effect-functions" json:"unsafe-no-effect-functions"`

	// Reflection is the reflection option of the pointer analysis: when true, reflection aperators are handled
	// soundly, but analysis time will increase dramatically.
	Reflection bool
}
