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

const (
	// DefaultSafeMaxDepth is the default maximum call stack value that will be considered by the analyses using it
	// -1 means that depth limit is ignored
	DefaultSafeMaxDepth = -1
	// DefaultSafeMaxEntrypointContextSize sets a context depth value that is usually safe in terms of algorithm performance.
	DefaultSafeMaxEntrypointContextSize = 5
	// EscapeBehaviorSummarize specifies that the function should be summarized in the escape analysis
	EscapeBehaviorSummarize = "summarize"
	// EscapeBehaviorNoop specifies that the function is a noop in the escape analysis
	EscapeBehaviorNoop = "noop"
	// EscapeBehaviorUnknown specifies that the function is "unknown" in the escape analysis
	EscapeBehaviorUnknown = "unknown"
)
