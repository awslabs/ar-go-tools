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

// ToolName is the type of tool names
type ToolName string

const (
	// AliasTool name
	AliasTool ToolName = "alias"
	// BacktraceTool name
	BacktraceTool ToolName = "backtrace"
	// CliTool name
	CliTool ToolName = "cli"
	// CompareTool name
	CompareTool ToolName = "compare"
	// DeferTool name
	DeferTool ToolName = "defer"
	// DependenciesTool name
	DependenciesTool ToolName = "dependencies"
	// GoroutineTool name
	GoroutineTool ToolName = "goroutine"
	// ImmutabilityTool name
	ImmutabilityTool ToolName = "immutability"
	// MayPanicTool name
	MayPanicTool ToolName = "maypanic"
	// PackageScanTool name
	PackageScanTool ToolName = "packagescan"
	// PassThruTool name
	PassThruTool ToolName = "diodon-passthru"
	// ReachabilityTool name
	ReachabilityTool ToolName = "reachability"
	// RenderTool name
	RenderTool ToolName = "render"
	// SsaStatisticsTool name
	SsaStatisticsTool ToolName = "ssa-statistics"
	// SyntacticTool name
	SyntacticTool ToolName = "syntactic"
	// TaintTool name
	TaintTool ToolName = "taint"
)
