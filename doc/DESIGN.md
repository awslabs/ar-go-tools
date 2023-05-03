# ARGOT: Automated Reasoning Go Tools

The Go programming language is a high-level programming language that is geared towards readability and usability for programmers aiming for highly performant distributed applications. Go is used at AWS to implement services and client-side functionality. In order to ensure that those programs are safe, programmers will need to rely on program analysis tools in order to automate the enforcement of safety properties.

## Problem

Program analysis tools can help developers safeguard their code against vulnerabilities, but also understand their code by taking different views of the program they write. Many of the analyses one could require can reuse the same underlying algorithms and reuse data obtained by other analyses, and successful approaches at designing analysis tools have consisted in packaging several analyses together to maximize reuse and provide more functionality to the user.

There are many analyses that have been implemented for the Go language ([Go vulnerability checking](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
[Go vet](https://pkg.go.dev/cmd/vet), [Go Flow Levee](https://github.com/google/go-flow-levee)), but those analyses have limitations and their use case does not match ours.
We need analyses that ensure the [soundness](https://cacm.acm.org/blogs/blog-cacm/236068-soundness-and-completeness-with-precision/fulltext) of their result, that is, ensure that if the code contains any error or any vulnerability, then the analysis will raise an alarm.
This is not the case for analyses that do code scanning only for example.

## Solution

The Automated Reasoning GO Tools (Argot) is a program analysis tool set, which at its core implements a whole-program dataflow analysis upon which other analyses are built. The main feature of this tool set is a tool for [**taint analysis**](https://en.wikipedia.org/wiki/Taint_checking), which is an approach to verifying that no sensitive data coming from a source reaches a function that should not handle such sensitive data. The tool set also contains functionality to analyze dependency imports, reachable function or apply a backward dataflow analysis among others.






# Overview

### Tools in Argot

The following tools are included in Argot:
- the `taint` tool allows you to perform taint analysis in your program.
- the `argot-cli` is an interactive analysis tool, which lets the user run multiple analyses on the program and inspect various levels of debugging information. This tool is intended for the advanced user who understands the underlying program representations more in detail.
- the `compare` tool, which can be used to compare the results of different reachability analyses together, on different platforms. This is useful for the user who wants to make sure the results given by some of the analyses are consistent with their assumptions, or the user that is trying to eliminate unneeded functions or dependencies.
- the `defer` tool runs an analysis that computes the possible deferred functions that can run at each return point of a function.
- the `dependencies` tool scans for the input package's dependencies and returns the list of dependencies along with the count of reachable functions within each dependency.
- the `maypanic` tool inspects the input packages to find any point in the code that may panic.
- the `packagescan` tool scans the input packages to find usages of specific packages in the code, such as usages of the `unsafe` package.
- the `reachability` tool inspects the code to find which functions are reachable, and which are not.
- the `render` tool can be used to render various representations of the code, such as its [Static Single Assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form) form or its callgraph.
- the `static-commands` tool analyzes the code to find usages of `os/exec.Command` that are defined statically.

### Configuration

The tools that require a configuration file (such as the `taint` and `argot-cli` tools) all use the same input format, which means that your configuration file can be reused across them. The goal is that the user configuration file corresponds to a specific program to analyze, and not a specific tool. The results of the different tools for the same program with the same configuration file will be consistent.
The config file is expected to be in YAML format. All fields are generally optional, unless required by a specific tool.
Some common optional fields across tools are:

```[yaml]
verbose: true                       # sets the output of the tool to verbose (internally default is false)
pkgfilter: "some-package/.*"        # filter which packages should be analyzed  (a regex matching package name)
skipinterprocedural: true           # skip the interprocedural pass if the tool has one (default is false)
coveragefilter: "other-package/.*"  # filter for which files to report coverage (a regex matching file paths)
reportsdir: "some-dir"              # where to store reports
reportcoverage: true                # whether to report coverage, if the analysis supports it (default false)
reportpaths: true                   # whether to report paths, if the analysis reports paths (default false)
reportnocalleesites: true           # whehter to report when callgraph analysis does not find a callee (default false)
maxalarms: 10                       # set a maximum for how many alarms are reported (default is 0 which means ignore)
filters:                            # a list of filters that is used by the analysis, the meaning is analysis dependent
    - "packages/*"
```

# Usage

## Taint Analysis

The taint analysis tool `taint` performs a whole program, interprocedural taint analysis on the input it is given. In this section we focus on explaining the user interface of the taint tool and give examples of what it can analyze. To understand how the taint analysis works, the reader should refer to the technical report (work in progress).

On top of the configuration options listed in the common fields, the user can configure taint-analysis specific options. The main configuration fields are the core components of the problem specification, which are the sources, sinks, sanitizers and validators of the dataflow problem. The *sources* identify the functions that return sensitive data, and this data should never reach any of the *sinks*. The *sanitizers* are functions that clear the data of its sensitive nature, i.e. those are functions that when receiving sensitive data, will return data that does not contain any sensitive information. *Validators* have a similar role, but do not return the data. When the value returned by a validator is a boolean and is true, then the data passed to the validator is considered to be taint-free in the branch where the boolean is true. When the value returned by a validator is an error, then the data is considered taint-free in the branch where the error is `nil`.

It is the user's responsibility to propery specify those functions to match their intent, and the tool does not try to automatically discover possible sources of tainted data, instead completely relying on the user's specification.

Below is an example of a config file containing a basic taint analysis specification:
```
sources:                        # A list of sources of tainted/sensitive data
    - package: "example1"
      method: "GetSensitiveData"

sinks:                          # A list of sinks that should not be reached by senstive data
    - package: "example2"
      method: "LogDataPublicly"

sanitizers:                     # A list of sanitizers that remove the taint from data
    - package: "example1"
      method: "Sanitize"

validators:                     # A list of validators that validates data, and removes taint when valid
    - package: "example3"
      method: "Validator"
```
In this configuration file, the user is trying to detect whether data coming from calls to some function `GetSensitiveData` in a package matching `example1` is flowing to a function `LogDataPublicly` in a package `example2`. If the data passes through a function `Sanitize` in the `example1` package, then it is santize. If the data is validated by the function `Validator` in package `example3`, then it is also taint-free.

An advanced feature of the taint analysis is that you can specify dataflow summaries yourself:
```
dataflowspecs:                  # A list of dataflow specifications, where each element is a json file containing
    - "specs-mylib.json"        # dataflow specifications.

```
We explain in more detail how to write [dataflow specifications](#dataflow-specifications) later, and why the user should write dataflow specifications in some cases.

### Examples

Taint analyses can vary a lot in their capacities. Some analyses are more geared towards precision and reporting fewer false alarms while others are geared towards soundness, that is, reporting all possible errors, or in this case, all possible flows from source to sink. Our analysis aims at the latter, which means that in some cases it may report false alarms. In the following we give examples that showcase the different types of taint flows that can be reported by the taint analysis tool. For a more in-depth understanding of the decisions made in the implementation, the technical report explains in detail how the analysis is built.

#### Simple Taint Flows


#### Inter-procedural Taint Flow


#### Field Sensitivity


#### Tuple Sensitivity


#### Closures



### Dataflow Specifications

Dataflow specifications allow the user to specify dataflows for functions in their program. The analysis tool will skip analyzing those functions, loading the dataflow specifited by the user instead. There are two kinds of user-specified dataflow summaries: summaries for functions, which specify the flow of data through a single function, and summaries for interface methods, which specify the flow of data through any of the interface method's implementation. The user must make sure that:
- in the case of a single function summary, the specified data flows subsumes any possible data flow in the function implementation
- for an interface method summary, the specified data flows subsumes any possible data flow, for any possible implementation

There are two reasons a user may want to specify a data flow summary:
- for performance: the analysis of some functions can take a lot of time, even though the flows of data can be summarized very succintly. This is the case for functions that have complex control flow and manipulate many data structures. It is also useful to summarize simple interfaces because this reduces the complexity of the call graph: a set of calls to every implementation of the interface is replaced by a single call to the summary for interface methods that are summarized by the user.
- for soundness: the analysis does not support reflection and some uses of the unsafe package. If a function uses those packages, then it should be summarized by the user. The analysis will raise alarms whenever some unsupported feature of the language is encountered during the analysis.

Dataflow specifications are json files that contain a list of specifications. Each specification is a structure that contains either an `"InterfaceId"` or an `"ObjectPath"`, along with a dictionary `"Methods"`. If an interface id is specified, then the dataflow specifications for each of the methods are interpreted as specifications for the interface methods, i.e. they specify every possible implementation of the interface. For example, consider the following dataflow specitifcations:
```[json]
[
    {
        "ObjectPath": "gopkg.in/yaml.v2",
        "Methods": {
            "Unmarshal": { "Args": [[0,1], [1]], "Rets": [[0],[0]] },
            "Marshal": { "Args": [ [ 0 ] ], "Rets": [ [ 0, 1 ] ] }
        }
    },
    {
        "InterfaceId": "io.Reader",
        "Methods": {
            "Read": { "Args": [ [ 0, 1 ], [ 0 ] ], "Rets": [ [ 0, 1 ], [ ] ] }
        }
    }
]
```
The first specification gives a dataflow summary for the functions `Unmarshal` and `Marshal` in the package `gopkg.in/yaml.v2`. The second specification gives a dataflow summary for the `Read` method of the `io.Reader` interface. That means that every implementation of `Read` will be replaced in the taint analysis by the dataflow summary specified in this file.

Each dataflow summary is of the form `{"Args":[...], "Rets": [...]}` where each list `[...]` is a list of lists of integers, and its length is the number of arguments of the function being summarized. In the "Args" list, the i-th list indicates that the data of the i-th argument flows to each argument index in the list. In the "Rets" list, this indicates that the i-th argument flows to each value index in the list. When nothing is returned, each list must be empty. When there is only one element returned (not a tuple), each list is [] or [0].

In the example, this means that the summary `"Marshal": { "Args": [ [ 0 ] ], "Rets": [ [ 0, 1 ] ] }` indicates that the data in the only argument of `Marshal` flows to itself (the `[0]` in "Args") and to both of the returned values (the `[0,1]` in "Rets").
In the specification for the `Reader` method, the first argument's data flows to both itself and the second argument, as specified by `[0,1]` in the first list, and the second argument only flows to itself, as specified by `[0]` in the second list.


>⚠️ Correct specification of the summaries is currently the user's responsibility, but we are working on tools to check the correctness of the summaries when the functions summarized are supported by the analysis.


### Interactive Analysis Tool



## Preliminaries: SSA, Pointer Analysis and Callgraph Construction

### Static Single Assignment (SSA) Form

Our analyses are built on a [Static Single Assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form) (SSA) representation of the Go program. The [ssa package](https://pkg.go.dev/golang.org/x/tools@v0.4.0/go/ssa#pkg-overview) provides functionalities to construct and manipulate a SSA represention of Go programs that is semantically equivalent to the original Go program but different from the Go compiler’s SSA forms. Compared to the compiler’s SSA form, the ssa package provides an intermediate representation that is directly accessible to the user and more amenable to classic analysis methods (visitor, control flow graph inspection, iterative monotone framework analyses). We opted for the ssa package representation to build our analysis.

### Pointer Analysis

A sound analysis requires a sound abstraction of the callgraph and the aliasing relations between values. The first step taken by our taint analysis is to build aliasing information using the pointer analysis in [golang.org/x/tools/go/pointer](https://pkg.go.dev/golang.org/x/tools/go/pointer) and to build a map from interface method types to their possible implementations.


### Sound Callgraph Approximation

A call instruction in the SSA may correspond to multiple *callees*; that is, there may be multiple functions called at runtime for the same SSA instruction. Resolving the callee of a callsite can often be done statically, but in other cases, there needs to be a static over-approximation of the set of callees at runtime.

In our implementation, the set of callees for a specific call instruction is decided as follows:

* if the instruction can only have one possible static callee, determined by the [StaticCallee()](https://pkg.go.dev/golang.org/x/tools@v0.4.0/go/ssa#CallCommon.StaticCallee) method of the ssa, then this is the only function that can be called by that instruction.
* otherwise, the callgraph built by the pointer analysis is queried for the set of functions that can be called. That set should be non-empty and it should overapproximate the set of possible callees at runtime,
* when the previous method fail, we return the set of all functions that implement the type or the method interface at the call site:
    * if the callsite is *invoking* an interface method, then the callees are all the possible implementations of that method.
    * if the callsite is calling a function stored in a variable, then the callees are all the possible functions of that type. We may be able to refine that set with some use-defs analysis that give a more precise idea of the possible values of the function.

## Function Summaries

*Here we discuss how we build function summaries, which abstract function bodies for the purpose of efficient data-flow analysis.
*

The intra-procedural pass searches for possible intra-procedural taint-flows and builds a data-flow summary for the function. The data-flow summary is a graph where each edge corresponds to a possible data flow between nodes. The node and graph definitions are in `analysis/taint/function_summary_graph.go` . The summary is a [SummaryGraph](https://quip-amazon.com/3DxdAkOuLBqb/Flowgot), and there are four types of nodes:

* parameter nodes - `[type ParamNode](https://gitlab.aws.dev/cm-arg/argot/-/blob/victor-dev/analysis/taint/function_summary_graph.go#L29)` represent parameter nodes. Edges starting at parameter nodes can flow to any other node in the graph, including other parameter nodes. For example, consider the following function definition:

```
func copy(s string, s2 *string) {
    *s2 = s
}
```

The summary of that function consists in two nodes (parameter nodes for `s` and `s2`) and one edge from `s` to `s2`. This means that any taint in `s` flows to `s2` when `copy` is called.

* callsite argument node - `[type CallNodeArg](https://gitlab.aws.dev/cm-arg/argot/-/blob/victor-dev/analysis/taint/function_summary_graph.go#L51)` - correspond to an argument of a specific callsite. Edges can flow to and from callsite arguments.
* callsite node - [`type CallNode`](https://gitlab.aws.dev/cm-arg/argot/-/blob/victor-dev/analysis/taint/function_summary_graph.go#L74) - represents a specific call site in a function body. Callsite nodes in the flow graph represent the return value of the function call, and therefore there are only edges *from* callsite nodes. Edges starting from a callsite node can flow into any other node, except callsite nodes.
    There may be more than one function that can be called at a callsite (more than one callee), and therefore, there may be more than one `CallNode` per callsite. However, a `CallNode` corresponds to a single callsite.
* return node - `[type ReturnNode](https://gitlab.aws.dev/cm-arg/argot/-/blob/victor-dev/analysis/taint/function_summary_graph.go#L105)` - represents a return node, associated with a specific instruction. There is one return node per return instruction in the ssa, and only edges flowing to the return node.

A directed edge between two nodes represents a possible data flow between those two nodes. At callsites, we have both the callsite nodes and the callsite argument nodes.


### Building the Summaries

The procedure that builds the dataflow summaries of the functions is an instance of the dataflow analysis with the monotone framework. Such an analysis is defined by a combination of a complete lattice and a set of monotone functions that define the dataflow constraints.



### Handling Go-Specific Constructs

#### Defers

Go has a special statement that allows the programmer to defer the execution of a function call until the caller returns. Two problems arise with handling defers in static analysis: (i) modelling defers is not as simple as moving the function call’s instruction just before the return statement of the caller and (ii) the stack of defer calls at a given return instruction cannot be determined statically.

(i) `defer` in Go defers the execution of the function call, but the arguments are evaluated when the defer is evaluated, not the when the function is executed. This means that value flow depends on the type of the argument: if the argument is passed by value, then the flow is decided where the `defer` instruction is. If the argument is passed by reference, then the flow is decided where the `return` of the function occurs.
Consider the following example:

```
a := "ok"
defer Sink(a) // ok
defer Sink2(&a) // alarm
a = Source()
return
```

Then the line `ok` will not raise an alarm: the value of `a`, which is `"ok"`, is passed to the call to `Sink`. Even though `Sink` is called when the function returns, the function call actually evaluated is `Sink(a)`. However, the line `alarm` will raise an alarm. `Sink2` is called with a reference to `a`, and when `Sink2` is evaluated, it receives the data returned by `Source()` .

(ii) We solve (ii) by over-approximating the possible stacks of defer calls at a given return instruction in the function. This is done by a simple reachability analysis which yields, for each return instruction, a set of possible stacks of defer instructions. This analysis is a strict over-approximation of the possible calls as long as there is no unbounded stack of defer function (e.g. defer called in a loop).



#### Goroutines

[TODO]


#### Closures

Go allows the programmer to manipulate higher-order functions and create closures: functions that reference variables outside their body. The challenge is that the variables bound by a closures (the variables referenced by a closure body that are defined in the enclosing function)

## Analyzing the Inter-Procedural Flow Graph

*Here we discuss how the inter-procedural flow graph is built and how we perform taint analysis on this graph.
*

The analysis needed to prove that commands are not executed without being validated requires an inter-procedural analysis: the calls to sources and sinks may be in different functions, and the data may flow across different function calls.

### Building the Inter-Procedural Flow Graph: Linking Function Summaries

Once all the necessary summaries have been computed, building the inter-procedural flow graph only consists in linking the summaries with each other.
Each `CallNode` has a `CalleeSummary` field that points to the summary of the function being called at that callsite. Recall that a callsite (an instruction in the function’s SSA) may correspond to multiple `CallNodes`, one for each possible callee. There is one single summary per callee, and therefore one summary per `CallNode`.

During the inter-procedural flow graph linking, each summary is also linked to all the possible `CallNodes` that refer to it (and, indirectly, all the callsites where the function may be called).

Once the inter-procedural flow graph is built, the taint analysis problem is reduced to a graph reachability problem.


### Analyzing the Inter-Procedural Flow Graph

Analyzing the inter-procedural flow graph consists in traversing the graph starting from a source node, until all reachable nodes are visited, while reporting if any sink node is reached.

Context-senstivity is obtained by keeping track of call stacks when visiting the call graph:
[TODO]


## Performance Improvements

### Embarrassingly Parallel Steps

The single-function summarization is a procedure that only writes information about a single function and reads information from the global program; it is an embarrasingly parallel step, in the sense that every function in the program to be analyzed can be processed in parallel. We take advantage of our design to provide an efficient implementation.

[TODO]


### Predefined Summaries

Our tool does not build summaries for the functions in the standard libraries, but instead relies on a set of predefined summaries for them.
[TODO]


# Appendix

Repository: https://gitlab.aws.dev/cm-arg/argot



### Comparison to other tools

We justify building our own tool by the limitations of existing Go analysis tools.
We have a [test suite](https://gitlab.aws.dev/cm-arg/ARG-GoAnalysisTests) that shows the differences in *soundness* and *precision*, showing that our tool outperforms others in both cases.


#### SSA Instructions

The SSA representation of the analysis pacakge is composed of 36 instructions. We list them with their notation in the following table. ⊕is some operator, and x, y and z are SSA values.

* A unary operation z=⊕ x
* A binary operation z=x⊕y


