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

// Package main provides the argot command-line tool for static analysis of Go programs.
//
// Argot is a collection of static analysis tools designed to help developers understand
// and verify properties of their Go code. The tools focus on dataflow analysis, security
// vulnerability detection, and code quality assessment.
//
// # Available Tools
//
// The following analysis tools are available as subcommands of the argot binary:
//
// ## Security and Dataflow Analysis
//
// taint - Performs whole-program taint analysis to detect flows of sensitive data
// from sources to sinks. This is the primary security analysis tool that can identify
// potential data leaks, injection vulnerabilities, and other security issues where
// untrusted data reaches sensitive operations.
//
// backtrace - Identifies backwards data-flow traces from specified function calls.
// This tool helps understand how data reaches particular program points by tracing
// all possible data flows in reverse.
//
// ## Interactive Analysis
//
// cli - Provides an interactive terminal-like interface for advanced program analysis.
// This tool allows users to load programs, inspect SSA representations, run pointer
// analysis, and examine dataflow summaries interactively. Intended for advanced users
// who need detailed program analysis capabilities.
//
// ## Code Quality and Structure
//
// dependencies - Analyzes package dependencies and reports usage statistics for each
// imported library. Helps identify underutilized dependencies that could be removed
// to reduce binary size and attack surface.
//
// reachability - Analyzes which functions are reachable from program entry points.
// Useful for understanding code coverage and identifying dead code.
//
// packagescan - Scans packages for usage of specific Go packages (like unsafe)
// or other patterns of interest.
//
// syntactic - Performs various syntactic analyses, such as checking that certain
// struct types are always initialized with specific values.
//
// ## Program Understanding
//
// render - Renders various program representations including Static Single Assignment
// (SSA) form and call graphs. Helps visualize program structure and control flow.
//
// compare - Compares results of different reachability analyses and binary analysis
// to understand differences between static analysis results and actual linking behavior.
//
// ## Specialized Analysis
//
// maypanic - Identifies goroutines that may have unrecovered panics, helping
// detect potential runtime failures in concurrent code.
//
// defer - Analyzes deferred function calls to determine which deferred functions
// may execute at each return point.
//
// # Configuration
//
// Most tools accept configuration files in YAML or JSON format that specify:
//   - Analysis problems (sources, sinks, sanitizers for taint analysis)
//   - Analysis options (logging level, package filters, output settings)
//   - Targets (specific files or packages to analyze)
//
// Tools that support configuration files include taint, backtrace, and cli.
// The configuration format is shared across these tools for consistency.
//
// # Usage Examples
//
// Basic taint analysis:
//
//	argot taint -config config.yaml ./path/to/code
//
// Interactive analysis:
//
//	argot cli -config config.yaml ./path/to/code
//
// Dependency analysis:
//
//	argot dependencies ./path/to/code
//
// Function reachability:
//
//	argot reachability ./path/to/code
//
// # Soundness and Limitations
//
// The dataflow analyses (taint and backtrace) provide soundness guarantees under
// certain conditions:
//   - No use of reflection or unsafe packages
//   - No concurrent access to shared memory (goroutines)
//   - Proper configuration of sources, sinks, and sanitizers
//
// When these conditions are not met, the tools will issue warnings but may still
// provide useful results for testing and understanding code behavior.
//
// For detailed documentation on each tool, see the doc/ directory in the project
// repository or run 'argot <tool> -help' for command-specific options.
package main
