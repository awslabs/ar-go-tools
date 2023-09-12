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

/*
Package taint implements most of the taint analysis functionality. It consumes the inter-procedural dataflow graph
that is built by the functions in the dataflow package. The main entry point of the analysis is the [Analyze] function,
which returns an [AnalysisResult] containing all the taint flows discovered as well as the analyzer state resulting
from running all the analyses.

When the analysis is not set to on-demand, the decision on summary building is encoded in [ShouldBuildSummary].

When the analysis is set to use the escape analysis, the taint analysis runs the escape analysis and the dataflow
analysis separately, and then cross-checks the results, making sure none of the tainted data ever escapes.
*/
package taint
