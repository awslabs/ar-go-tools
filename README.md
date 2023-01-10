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
`./taint/ssm-agent`
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
pkgprefix: "github.com/aws" # focus on functions in aws
coveragefile: "taint-coverage.out" # output the lines covered by the taint flow propagation
coverage: "amazon-ssm-agent/agent" # coverage is only reported for those file that have amazon-ssm-agent/agent as substring
outputsummaries: true
sources:
   - method: "GetMessages"
     package: "github.com/aws/amazon-ssm-agent/agent/runcommand/mds"
sinks:
  - package: "github.com/aws/amazon-ssm-agent/agent/jsonutil"
    method: "Marshal"
  - method: "(.*)Submit"
```
- The `pkgprefix` option specifies which files to analyze: summaries will be built only for the functions that have a 
package name that starts with this prefix. 
- The `coveragefile` option specifies where the coverage file output should be written. One can then use
`go tool cover -html=coveragefilename` to inspect which lines have been reached by tainted data. `coverage` specifies
for which files coverage needs to be reported; in this example, any file that contains `amazon-ssm-agent/agent` in 
its path.
- The `outputsummaries` option is a boolean that specifies whether a representation of the summaries needs to be 
produced. If set to true, the dataflow summaries can be inspected in the `flow-summaries.out` file in the same folder
where the tool is run.
- The `sources` and `sinks` each specify sets of identifiers for sources and sinks. A source can be specified by a 
method (or function) name with `method` or a field name with `field`. A sink must be a function (or method). The 
`package` information narrows down how function, methods and fields are matched. Note that the strings are Go regexes.
For example, in the test files, one can specify the package as `(main|command-line-arguments)` to allow for the 
different ways the main package could be loaded.