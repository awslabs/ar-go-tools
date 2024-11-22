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
Package dataflow implements the core of the dataflow analysis. In order to run the taint or the backwards
analysis, you should first run the steps to build the inter-procedural dataflow graph.

The first object to build is an instance of the [State] with some basic analyses's results already computed.
Assuming you have a pointer state, you can build an initialized state for your program using the [NewState] function:

	state, err := dataflow.NewState(ptrState)

This initialization runs the pointer analysis on the program, as well as a scanning step for global variables, interface
method implementations and variable bounding information.

To build the dataflow summary of a single function, run the [IntraProceduralAnalysis] function, which runs the
intra-procedural analysis on the function:

	id := 0 // some id for the summary
	isEntryPoint // some function that identifies entry points for your analyses
	postBlockCallBack // optional, some function that get called after each block is analyzed
	shouldBuildSummary // this indicates when the summary should be built, as opposed to simply be created
	dataflow.IntraProceduralAnalysis(state, function, shouldBuildSummary, id, isEntryPoint, postBlockCallback)
*/
package dataflow
