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
Package config provides a simple way to manage configuration files.

Use [Load](filename) to load a configuration from a specific filename.

Use [SetGlobalConfig](filename) to set filename as the global config, and then [LoadGlobal]() to load the global config.

# Configuration File Format

A config file should be in YAML or JSON format. The top-level fields can be any of the fields defined in the Config
struct type. The configuration is organized into several main sections:

## Global Options

The `options` section contains global analysis settings:

	options:
	  project-root: "../../"           # Root directory for relative paths
	  reports-dir: "logs/argot"        # Directory for analysis reports
	  log-level: 3                     # Verbosity level (1=Error, 2=Warn, 3=Info, 4=Debug, 5=Trace)
	  report-paths: true               # Generate detailed path reports
	  analysis-options:
	    unsafe-max-depth: 15           # Limit call depth (unsafe if > 0)
	    max-alarms: 30                 # Maximum number of alarms to report

## Pointer Analysis Configuration

The `pointer-config` section controls pointer analysis behavior:

	pointer-config:
	  unsafe-no-effect-functions:      # Functions ignored for aliasing
	    - fmt.Errorf
	    - log.Errorf

## Analysis Targets

The `targets` section defines analysis targets (sets of files that form a program):

	targets:
	  - name: "project-name-unix"
	    files: ["core/daemon.go", "core/daemon_unix.go"]
	  - name: "project-name-windows"
	    files: ["core/daemon.go", "core/daemon_windows.go"]
	    platform: "windows"

## Dataflow Problems

The `dataflow-problems` section configures taint tracking and slicing analyses:

	dataflow-problems:
	  summarize-on-demand: true
	  field-sensitive-funcs: [".*"]
	  user-specs: ["specifications/std-specs.json"]

	  # Taint tracking problems
	  taint-tracking:
	    - tag: "credential-logging"
	      description: "Checking that credentials don't get logged."
	      targets: ["project-name-unix", "project-name-windows"]
	      unsafe-skip-bound-labels: false
	      severity: "HIGH"
	      sources:
	        - package: "credentials"
	          method: "Get"
	      sinks:
	        - context: "project-name"
	          method: "^(Log|Error|Warn|Debug|Info|Print).*"
	      sanitizers:
	        - package: ".*signer/v4"
	          method: "Sign"

	  # Slicing problems (backward dataflow)
	  slicing:
	    - tag: "must-compile-must-be-const"
	      description: "Checking that regexp.MustCompile arguments are statically defined."
	      targets: ["project-name-unix"]
	      must-be-static: true
	      backtracepoints:
	        - package: "regexp"
	          method: "^MustCompile$"

## Syntactic Problems

The `syntactic-problems` section defines syntactic analysis checks:

	syntactic-problems:
	  # Struct initialization checks
	  struct-inits:
	    - tag: "init-tls-v12"
	      description: "Check that tls.Config is initialized with TLS 1.2"
	      targets: ["project-name-unix"]
	      struct:
	        type: "crypto/tls.Config"
	      fields-set:
	        - field: "MinVersion"
	          value:
	            package: "crypto/tls"
	            const: "VersionTLS12"

	  # Conditional checks
	  cond-checks:
	    - tag: "resource-check-availability"
	      description: "daemon must check resource availability before performing changes"
	      targets: ["project-name-unix"]
	      call:
	        - method: "DownloadUpdater$"
	      preconditions:
	        - precondition: ["IsDiskSpaceSufficientForUpdate(...)#0"]

# Code Identifiers

The config uses [CodeIdentifier] to identify specific code entities. Code identifiers can specify:
- `package`: Package name or regex pattern
- `method`: Method/function name or regex pattern
- `type`: Type name or regex pattern
- `context`: Context name or regex pattern
- `const`: Constant name

String specifications are treated as regexes if they can be compiled as such, otherwise as literal strings.

# Severity Levels

Findings can have severity levels: "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL".

# Unsafe Options

All options that might affect soundness are prefixed with `unsafe-`, except for user-provided function summaries
(where the user is assumed to have soundly summarized the functions).
*/
package config
