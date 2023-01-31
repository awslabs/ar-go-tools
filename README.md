[![pipeline status](https://gitlab.aws.dev/cm-arg/argot/badges/mainline/pipeline.svg)](https://gitlab.aws.dev/cm-arg/argot/-/commits/mainline)
[![coverage report](https://gitlab.aws.dev/cm-arg/argot/badges/mainline/coverage.svg)](https://gitlab.aws.dev/cm-arg/argot/-/commits/mainline) 
[![Latest Release](https://gitlab.aws.dev/cm-arg/argot/-/badges/release.svg)](https://gitlab.aws.dev/cm-arg/argot/-/releases)

# Argot

Argot is Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.

## Overview

Argot is a collection of tools:
-  `compare` prints a comparison of the functions that are reachable according to two different analyses, and the 
functions that appear in the binary.
- `dependencies` prints the dependencies of a given program.
- `maypanic` performs a may-panic analysis on a given program.
- `reachability` analyzes the program an prints the functions that are reachable within it.
- `render` can be used to render a graph representation of the callgraph, or to print the SSA form from the go analysis
package.
- `static-commands` identifies calls to command running executables with static arguments.
- `statistics` prints statistics about the program.
- `taint` performs a taint analysis on a given program.

### Building the tools
The `Makefile` at the project root will call `go build` for each of the tools. 

### Running the tools

#### Compare
You can compare the set of reachable functions according to a reachability analysis use in Argot, a reachability 
analysis built on a callgraph construction method available in the `x/tools` packages, and the functions appearing 
in a binary. 
For example, to run the comparison for the compare executable:
```shell
go nm bin/compare > compare-symbols # Extract the symbols in the binary bin/compare
./bin/compare -binary compare-symbols -analysis cha ./cmd/compare/main.go ./cmd/compare/loadsymbols.go
```
By default, the tool uses the `pointer` analysis, which should have fewer reachable functions.

#### Dependencies
See [scripts/ssm-dependencies](scripts/ssm-dependencies) for an example of how to run the dependency tool.

#### Maypanic
See [scripts/ssm-may-panic](scripts/ssm-may-panic) for an example of how to run the may-panic analysis.

#### Reachability

TODO

#### Render
In order to print the SSA form of a program, run the following:
```shell
./bin/render -ssaout tmp myprogram
```
The tool will create a folder tmp and for each package in `myprogram` generate a SSA file. Packages that belong to the
same module will be in the same folder. For example, try running:
```shell
./bin/render --ssaout tmp ./cmd/render/main.go
```
You will find a file called `fmt.ssa` in the folder `tmp` corresponding to the `fmt` package. The folder
`tmp/git.amazon.com/ARG-Go-Analyzer` will contain the ssa representations of the packages defined in this project.

If you want to generate the callgraph of a program, run the following:
```shell
./bin/render [-analysis (pointer|cha|rta|static|vta)] -cgout graph.dot ./cmd/render/main.go
```
Where the `-analysis` is the type of analysis to run to build the callgraph. By default, the buildmode is `pointer`,
and the tool runs a pointer analysis using the [pointer package](https://pkg.go.dev/golang.org/x/tools/go/pointer)

#### Static-Commands

TODO

#### Statistics
For example, run:
```shell
./bin/statistics cmd/statistics/main.go
```

#### Taint

This tool is still under construction.
You can try running:
```shell
./bin/taint cmd/taint/main.go
```
Which will run the analysis without searching for sources and sinks but will build all the data flow summaries it would
need to perform the taint analysis.

The `scripts` folder contains a script to run the `taint` tool on the SSM agent:
`./scripts/ssm-taint`
Note that there will be warnings and errors, since the implementation is not complete. You will see the different 
passes of the analysis running:
- constructing the callgraph and building aliasing information (pointer analysis)
- constructing the function summaries and detecting intra-procedural taint flows (intra-procedural analysis)
- traversing the inter-procedural flow graph from taint sources (inter-procedural analysis)

#### Taint Analysis Config File
The taint analysis uses a config file that contains the definition of the sinks and sources to be considered, as well
as various configuration options. Several examples are in the `testdata` examples. The configuration file for the agent
analysis contains the following:
```yaml
# Report all data
reportsdir: "taint-report" # report will be in subdirectory taint-report where this file is
reportcoverage: true
reportsummaries: true
reportpaths: true
coverage: "amazon-ssm-agent/agent" # coverage is only reported for those file that have amazon-ssm-agent/agent as substring
# Use interface contracts
dataflowspecs: "agent-specs.json"
pkgprefix: "github.com/aws" # focus on functions in aws
sources:
   - method: "GetMessages"
     package: "github.com/aws/amazon-ssm-agent/agent/runcommand/mds"
sinks:
  - package: "github.com/aws/amazon-ssm-agent/agent/jsonutil"
    method: "Marshal"
  - method: "(.*)Submit"
```
The first configuration options are for the output of the tool. 
- The `reportsdir` option specifies where the output files should be written. If the directory doesn't exist, it will 
be created. When running the script, this means all the output will be in `amazon-ssm-agent/taint-report`.
- The `reportcoverage` option is set to true to enable reporting coverage for the taint analysis. For each run, a new
temporary file with a name matching `coverage-*.out` will be generated. You can inspect the coverage using the 
usual Go tool (e.g. `go tool cover -html=amazon-ssm-agent/taint-report/coverage-*.out`)
- The `reportsummaries` option is set to enable reporting the dataflow summaries built for the function in the agent.
Look for a file with a name matching `summaries-*.out` in the report folder.
- The `reportpaths` option enables reporting the taint flows from source to sink. For each flow, one report file with 
a name matching `flow-*.out` will be created in the report folder.

The other options change the behaviour of the analysis itself:
- The `pkgprefix` option specifies which files to analyze: summaries will be built only for the functions that have a 
package name that starts with this prefix.
- The `dataflowspecs` specifies a JSON file that contains dataflow summaries for interfaces. The tool will use those
summaries to replace calls to interface methods, greatly reducing the complexity of the cross-function flow analysis.
- The `sources` and `sinks` each specify sets of identifiers for sources and sinks. A source can be specified by a 
method (or function) name with `method` or a field name with `field`. A sink must be a function (or method). The 
`package` information narrows down how function, methods and fields are matched. Note that the strings are Go regexes.
For example, in the test files, one can specify the package as `(main|command-line-arguments)` to allow for the 
different ways the main package could be loaded.
