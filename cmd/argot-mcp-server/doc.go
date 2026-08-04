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

// Package main provides the argot-mcp-server, an MCP (Model Context Protocol) server
// that exposes Argot's static analysis capabilities to AI assistants and other clients.
//
// The server implements the Model Context Protocol specification, enabling interactive
// Go code analysis through a standardized JSON-RPC 2.0 interface over stdin/stdout.
//
// # Available Tools
//
// The MCP server provides stateful access to Argot's analysis capabilities:
//
// Program Management:
//   - argot_load: Load Go programs for analysis
//   - argot_program_rebuild: Rebuild loaded programs
//   - argot_show_state: Display current analysis state
//
// Code Discovery:
//   - argot_list_functions: List functions matching patterns
//   - argot_members: Show package members
//   - argot_show_src: Display source code
//   - argot_print_ast: Show Abstract Syntax Tree
//   - argot_show_ssa: Display SSA representation
//   - argot_scan: Scan AST for patterns
//
// Analysis Tools:
//   - argot_run_pointer: Execute pointer analysis
//   - argot_dataflow_summarize: Build dataflow summaries
//   - argot_show_callees/callers: Show call relationships
//   - go_dependencies: Analyze package dependencies
//   - check_summary_valid: Validate a dataflow summaries file/content for well-formedness
//     problems (e.g. self-flows) detectable without loading a program
//
// Function-Level Analysis (requires focused function):
//   - argot_function_focus/unfocus: Focus on specific functions
//   - argot_show_ssa_value/instr: Examine SSA details
//   - argot_focused_mayalias: Check value aliasing
//
// # Available Prompts
//
// dataflow-summary-generation: Comprehensive prompt for generating dataflow
// summaries for Go functions, including complete YAML format specifications
// and step-by-step analysis workflow.
//
// # Usage
// Install:
//
// go install github.com/awslabs/ar-go-tools/cmd/argot-mcp-server@latest
//
// Start the server:
//
//	argot-mcp-server
//
// The server communicates via stdin/stdout using JSON-RPC 2.0.
//
// Typical workflow:
//  1. Load a program with argot_load
//  2. Discover functions with argot_list_functions
//  3. Inspect code with argot_show_src/argot_show_ssa
//  4. Run analyses like argot_run_pointer
//  5. Generate summaries with dataflow-summary-generation prompt
//
// # Integration
//
// Configure in MCP client settings:
//
//	{
//	  "mcpServers": {
//	    "argot": {
//	      "command": "argot-mcp-server",
//	      "args": []
//	    }
//	  }
//	}
package main
