[![pipeline status](https://gitlab.aws.dev/cm-arg/argot/badges/mainline/pipeline.svg)](https://gitlab.aws.dev/cm-arg/argot/-/commits/mainline)
[![coverage report](https://gitlab.aws.dev/cm-arg/argot/badges/mainline/coverage.svg)](https://gitlab.aws.dev/cm-arg/argot/-/commits/mainline)
[![Latest Release](https://gitlab.aws.dev/cm-arg/argot/-/badges/release.svg)](https://gitlab.aws.dev/cm-arg/argot/-/releases)

# Argot

## Overview

Argot is a collection of tools:
- `argot-cli` is a terminal-like interface for various part of the analysis (in `cmd/cli`)
- `compare` prints a comparison of the functions that are reachable according to two different analyses, and the
functions that appear in the binary,
- `dependencies` prints the dependencies of a given program,
- `maypanic` performs a may-panic analysis on a given program,
- `packagescan` scans imports in packages,
- `reachability` analyzes the program an prints the functions that are reachable within it,
- `render` can be used to render a graph representation of the callgraph, or to print the SSA form from the go analysis
package,
- `static-commands` identifies calls to command running executables with static arguments,
- `statistics` prints statistics about the program,
- `taint` performs a taint analysis on a given program.

### Building the tools
The `Makefile` at the project root will call `go build` for each of the tools.

### Running the tools

#### Command-Line Tool

The command-line tool `argot-cli` allows you to inspect the different results of the analyses interactively. The cli
tool expects a program as argument and a configuration file. For example, run:
```shell
./bin/argot-cli -config testdata/src/taint/example1/config.yaml testdata/src/taint/example1/main.go
```
The cli will load the program and run the pointer and callgraph analyses. If no config file is specified, and the
program is only one main file, then the tool will look for a `config.yaml` file in the same directory as the `main.go`
file. It will always require some config file.

Once the program building step has terminated,  you should see a prompt. Typing `help` will print a list of all
the commands available. `exit` exits the tool. For example, the `list` command lets you print a list of functions
matching a given regex:
```shell
> list command-line-arguments
```
Will print all the functions in the `command-line-arguments` package, which is the main package loaded by the go
analysis tool.

A typical workflow to run taint analyses is to build the summaries of all necessary functions by running the command:
```shell
> summarize
```
And then build the cross-function flow graph:
```shell
> buildgraph
```
And finally run the taint analysis:
```shell
> taint
```
At any point you can rebuild the program by using `rebuild` and reload the configuration by using `reconfig`. This is
particularly useful if you want to modify source and sink definitions without having to reload the program and run the
analyses.


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
`tmp/github.com/awslabs/argot` will contain the ssa representations of the packages defined in this project.

If you want to generate the callgraph of a program, run the following:
```shell
./bin/render [-analysis (pointer|cha|rta|static|vta)] -cgout graph.dot ./cmd/render/main.go
```
Where the `-analysis` is the type of analysis to run to build the callgraph. By default, the buildmode is `pointer`,
and the tool runs a pointer analysis using the [pointer package](https://pkg.go.dev/golang.org/x/tools/go/pointer)

In order to generate an SVG file `df.svg` of the cross-function dataflow graph of the program
`./testdata/src/taint/summaries/main.go`, run the following:
``` shell
./bin/render -dfout=df.dot -config=./testdata/src/taint/summaries/config.yaml ./testdata/src/taint/summaries/main.go && dot -Tsvg df.dot -o df.svg
```

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

#### Taint Analysis Config File
The taint analysis uses a config file that contains the definition of the sinks and sources to be considered, as well
as various configuration options. Several examples are in the `testdata` examples.
For example, here is a configuration file:
```yaml
# Report all data
reportsdir: "taint-report" # report will be in subdirectory taint-report where this file is
reportcoverage: true
reportsummaries: true
reportpaths: true
maxdepth: 46 # Optional setting to limit runtime; a call depth of 46 is safe
coveragefilter: "module/package" # coverage is only reported for files matching
# Use interface contracts
dataflowspecs: "specs.json"
pkgfilter: "github.com/module1" # focus on functions in module1
sources:
  - method: "GetMessage"
    package: "github.com/module1/packageX"
sinks:
  - method: "Execute"
    package: "github.com/module1/packageY"
```
The first configuration options are for the output of the tool.
- The `reportsdir` option specifies where the output files should be written. If the directory doesn't exist, it will
be created. In this example, all the outputs will be in `taint-report`.
- The `reportcoverage` option is set to true to enable reporting coverage for the taint analysis. For each run, a new
temporary file with a name matching `coverage-*.out` will be generated. You can inspect the coverage using the
usual Go tool (e.g. `go tool cover -html=taint-report/coverage-*.out`)
- The `reportsummaries` option is set to enable reporting the dataflow summaries built for the functions analyzed.
Look for a file with a name matching `summaries-*.out` in the report folder.
- The `reportpaths` option enables reporting the taint flows from source to sink. For each flow, one report file with
a name matching `flow-*.out` will be created in the report folder.

The other options change the behaviour of the analysis itself:
- The `pkgfilter` option specifies a regex to filter which functions to analyze: only those functions whose package
name matches the regex are analyzed.
- The `dataflowspecs` specifies a list of JSON files that contains dataflow summaries for interfaces. The tool will
use those summaries to replace calls to interface methods, greatly reducing the complexity of the cross-function flow
 analysis.
- The `maxdepth` sets the maximum callstack size above which paths are discarded in the analysis. This option allows
to reduce the runtime at the expense of soundness. However, large values should be safe. For example, in the scripts,
no additional paths will be discovered with a higher value of the depth.
- The `sources` and `sinks` each specify sets of identifiers for sources and sinks. A source can be specified by a
method (or function) name with `method` or a field name with `field`. A sink must be a function (or method). The
`package` information narrows down how function, methods and fields are matched. Note that the strings are Go regexes.
For example, in the test files, one can specify the package as `(main|command-line-arguments)` to allow for the
different ways the main package could be loaded.

## Source Code Organization

The executables are in the `cmd` folder, we have one executable per tool listed.

The test data is in the `testdata` folder. All the Go source files used in the tests are in `testdata/src`.

The library code, and most of the analysis implementations, is in the `analysis` folder. The main entry points are in
the `load_progam.go` file for loading progam and `analyzers.go` to call analyzers. The rest is organized in subfolders:
- `astfuncs` contains functions for manipulating the Go AST,
- `closures` contains analysis code specific to closures in Go,
- `concurrency` contains the concurrency analyses,
- `config` implements the config file system that is shared by all analyses,
- `dataflow` implements the dataflow analysis as well as the analysis state object, which is shared by many analyses.
Static analyses that required pointer and callgraph information should depend on the dataflow analysis state and use its
 functionality to build information about the SSA program.
- `defers` contains the defers analysis,
- `dependencies` contains the dependencies analysis,
- `format` contains formatting helpers,
- `functional` implements some functional-style programming idioms, such as a `Map` function for slices and some data
structures.
- `graph-ops` implements graph operations on the callgraph. This can be used to collect information about the callgraph,
compute subsets of the callgraph, strongly connected components, etc.
- `maypanic` contains the may-panic analysis,
- `packagescan` contains the packagescan analysis,
- `reachability` contains function-reachability analyses
- `refactor` contains implements refactoring operations,
- `rendering` implements rendering functions, such as printing the SSA output or representing the callgraph in various
formats,
- `lang` contains function for manipulating the Go SSA form (from the x/tools packages),
- `static-commands` implements the static command detection analysis,
- `summaries` defines dataflow summaries of some functions,
- `taint` implements the taint analysis
- `utils` contains some utility functions.