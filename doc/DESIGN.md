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

The taint analysis tool `taint` performs a whole program, interprocedural taint analysis on the input program that is given. In this section we focus on explaining the user interface of the taint tool and give examples of what it can analyze. To understand how the taint analysis works, the reader should refer to the technical report (work in progress). Here we explain *how to use the taint analysis tool* through a set of examples (in [Taint Analysis Examples](#taint-analysis-examples)).

The tool will report flows from taint **sources** to **sinks**, taking in account **sanitizers** and **validators**. Those components are specified in the configuration file by the user (see [Taint Analysis Configuration](#taint-analysis-configuration)). The tool will output traces for each of the traces detected (and additional information if specified in the configuration file) (see [Taint Analysis Output](#taint-analysis-output)).

> ⚠ The taint analysis does not support usages of the `reflect` and `unsafe` packages. We explain later how to analyze programs in the presence of those, but the result is not guaranteed to be correct when the analysis raises no alarms.

### Taint Analysis Configuration
On top of the configuration options listed in the common fields, the user can configure taint-analysis specific options. The main configuration fields are the core components of the problem specification, which are the sources, sinks, sanitizers and validators of the dataflow problem. The *sources* identify the functions that return sensitive data, and this data should never reach any of the *sinks*. The *sanitizers* are functions that clear the data of its sensitive nature, i.e. those are functions that when receiving sensitive data, will return data that does not contain any sensitive information. *Validators* have a similar role, but do not return the data. When the value returned by a validator is a boolean and is true, then the data passed to the validator is considered to be taint-free in the branch where the boolean is true. When the value returned by a validator is an error, then the data is considered taint-free in the branch where the error is `nil`.

It is the user's responsibility to properly specify those functions to match their intent, and the tool does not try to automatically discover possible sources of tainted data, instead completely relying on the user's specification.

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

### Taint Analysis Output

TODO: describe the output of the analysis

### Taint Analysis Examples

Taint analyses can vary a lot in their capacities. Some analyses are more geared towards precision and reporting fewer false alarms while others are geared towards soundness, that is, reporting all possible errors, or in this case, all possible flows from source to sink. Our analysis aims at the latter, which means that in some cases it may report false alarms. In the following we give examples that showcase the different types of taint flows that can be reported by the taint analysis tool. For a more in-depth understanding of the decisions made in the implementation, the technical report explains in detail how the analysis is built.

#### Simple Taint Flows
Our taint analysis in general assumes that any operation propagates taint. For example, if a string is tainted, then adding elements to it, or taking a slice of the string, will produce tainted data.
```[go]
func main() {
    x := example1.GetSensitiveData() // x is tainted
    y := "(" + x + ")" // y is tainted because x is tainted
    example2.LogDataPublicly(y) // an alarm is raised because tainted data reaches the sink
}
```
Given the above example, and the previous configuration file, the call to `example1.GetSensitiveData` is identified as a source: the data it returns is tainted. The call to `example2.LogDataPublicly` is identified as a sink: if any argument that is passed contains tainted data, an alarm is raised and the tool will print a trace from the point where the data is tainted (by a source) to the sink it reached. In this example, there is such a trace: the analysis sees `y` as tainted because it directly depends on `x`'s data.

In general, the analysis is conservative in how it propagates data: for example, if a cell of a slice gets tainted, then the entire slice is considered tainted, or if one entry in a map is tainted, then the entire map is viewed as tainted. The analysis also tracks aliases, and therefore tainting a variable will taint all its aliases.

#### Inter-procedural Taint Flow

The taint analysis implemented in Argot is *inter-procedural*: the flow of data is tracked across function calls, as opposed to within a single function. This means that the flow of tainted data is detected in the following example:
```[go]
func generate() *A {
    x := example1.GetSensitiveData() // this is a source of sensitive data
    return x
}

// Copy Data field from src to dest
func copyData(src *A, dest *A) {
    a1.Data = a2.Data
}


func main() {
    a := generate()
    b := NewA()
    copyData(a,b)
    example2.LogDataPublicly(b) // this is a sink that should not be reached by sensitive data
}

```

The `taint` tool will report taint flows given the configuration example given previously and the snippet of code above in some context where all functions are properly defined. The data flows from the call to `example1.GetSensitiveData()` in `generate()`, to the variable `a`, then to `b` through the `copyData` function, and then finally to the call to `example2.LogDataPublicly(b)` in the `main()` function. Detecting this type of path would not be possible without an inter-procedural analysis.

The taint analysis tool can detect such flows with many intermediate calls.

> 📝 To limit the size of the traces reported by the tool, one can limit how many functions deep the trace can be using the `maxdepth: [some integer]` option in the configuration file. Note that if this option is used, then the tool may not report some taint flows. In the previous example, the trace would not be reported if the configuration file sets `maxdepth: 2`.


#### Field Sensitivity

The taint analysis is not *field-sensitive*: if a field from a structure is tainted, then the entire object is tainted. This means that the tool may raise false alarms, as illustrated in the following example:
```[go]
func main() {
    a := A{}
    a.Data = "safe-data" // the Data field does not contain sensitive data
    a.Secret = example1.GetSensitiveData() // Secret field does

    example2.LogDataPublicly(a.Data) // an alarm is raised here at the sink
}
```
In this example, with the configuration used previsouly, an alarm is raised: the data flows from the call to `GetSensitiveData` to the call to `LogDataPublicly`. When the `Secret` field is assigned tainted data, the entire structure `a` is considered tainted. This means that `a.Data` is considered tainted in the call to the sink function.
If the analysis was field-sensitive, it would not raise an alarm.


#### Tuple Sensitivity

The taint analysis is *tuple-sensitive*: it tracks the taint of different elements of the tuple separately. This is easier in Go than in other languages because tuples only exist at the boundary of function calls an returns, they cannot be manipulated elsewhere in the code.
This means that in the following example, no false alarm is raised:
```[go]

// generate returns a tuple of values, one of which is tainted
func generate() (*A, string) {
    return example1.GetSensitiveData(), someSafeData()
}

func main() {
    x, y := generate() // only x is tainted, y is not
    example2.LogDataPublicly(y) // this does not raise any alarms
}

```
Because the analysis tracks the taint of the tuple elements separately, it detects that `x` is tainted but `y` is not tainted in the example. This means that the call to `LogDataPublicly` is safe, and not alarm is raised.


#### Closures

[Closures](https://go.dev/tour/moretypes/25) are functions that can reference variables (*bound* variables) from outside their body. This referencing makes the taint analysis more complicated, as the data may flow from aliases of the variables *bound* by a closure to the point where the closure is executed. Our taint analysis tool is able to trace the flow of data in the presence of closures.

For example, in the following:
```[go]
func example3prep() func(string) string {
	lparen := "("
	rparen := ")"
	parenthesize := func(a string) string { return lparen + a + rparen } // rparen is captured
	rparen = example1.GetSensitiveData() // rparent is tainted after being captured
	return parenthesize
}

func example3() {
	closure := example3prep()
	x := closure("A") // when closure is called, rparent was tainted, so x is tainted
	example2.LogDataPublicly(x) // this raises an alarm
}
```
An alarm is raised because data flows from the source to the sink. When the closure is created, it captures the variable `rparen`, which is initially not tainted (it is equal to `")"`). After the closure has been created and assigned to the `parenthesize` variable, `rparen` is tainted. This means that any subsequent call to `parenthesize` will read the tainted value of `rparen` and return tainted data. This is properly tracked when `closure` is called, resulting in tainted data in `x`.

### Defers

[Defers](https://go.dev/tour/flowcontrol/12) are a Go specific feature: it defers the execution of a function until the surrounding function returns, or the function panics. Because of the latter, our analysis needs to be conservative when analyzing what data flows through deferred functions. It assumes that the deferred functions can be executed *at any point* in the surrounding functions, simulating any possible panic.

The following example illustrates a taint flow to a deferred function, the difference between the two calls is that one captures its argument by reference:

```[go]
func main() {
	a := A{"ok"}
	b := &A{"ok"}
	defer example2.LogDataPublicly(a)    // does not raise alarm, b is a value A
	defer example2.LogDataPublicly(b)   // will raise alarm, b is &A
	a = example1.GetSensitiveData()     // the value a is now tainted, but never used
    *b = example1.GetSensitiveData()   // the value *b is tainted, and b will be read in the deferred function
}
```
In the example, the calls to the sink `LogDataPublicly` are deferred until the end of the function. Because the first call takes `a` as argument, and `a` is a non-tainted value, this does not raise an alarm. The arguments of a deferred call are evaluated at the `defer` location. However, in the second call, the argument passed is a pointer to some structure, which is tainted later. In this case, an alarm is raised.

Let us consider another example that illustrate the flows through defers, when defers can execute at any point of the function.
```[go]
func maypanic(x *Obj, b string) {
	defer func() {
		x.f = b
	}()
	bar()   // may panic here, and so defer may be executed
	b = "0" // clears taint from b
	return
}

func catchPanic(x *Obj, b string) {
	defer func() { recover() }()
	maypanic(x, b)
}

func main2() {
	x := &Obj{}
	b := example1.GetSensitiveData() // data is tainted here
	catchPanic(x, b)  // catchPanic may cause x to be tainted if bar panics
	example2.LogDataPublicly(x.f) // an alarm is raised here
}
```
In this example, the taint may flow from `b` to `x` in `catchPanic` through `maypanic`, assuming for example that the `bar()` function may panic. When `bar()` does not panic, `b` is cleared of the taint, and `x.f` is not tainted by the defer. However, if `bar()` panics, the deferred function executes in a state where `b` is tainted, and therefore `x` gets tainted. Because `catchPanic` recovers from the panic, `x` will be tainted when `catchPanic` returns. The taint tool correctly catches this possible taint flow.

> ⚠️ Programmers should not rely on reinitializing variables to clear taint inside of arbitrary functions. Instead, sanitize or validate the data in a clearly delineated function, where all possible execution paths can be carefully examined. The taint tool is conservative with respect to possible execution of defers and may raise false alarms, but it will raise fewer false alarms if the sanitization is properly done within the designated sanitizer function. However, it is the user's responsibility to ensure the sanitizer does the sanitization.


## Dataflow Specifications

Dataflow specifications allow the user to specify dataflows for functions in their program. The analysis tool will skip analyzing those functions, loading the dataflow specified by the user instead. There are two kinds of user-specified dataflow summaries: summaries for functions, which specify the flow of data through a single function, and summaries for interface methods, which specify the flow of data through any of the interface method's implementation. The user must make sure that:
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


