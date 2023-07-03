# Taint Analysis

The taint analysis tool `taint` performs a whole program, interprocedural taint analysis on the input program that is given. It is not necessary to understand those terms in order to use the tool. In this section we focus on explaining the user interface of the taint tool and give examples of what it can analyze. To understand how the taint analysis works, the reader should refer to the technical report (work in progress). Here we explain *how to use the taint analysis tool* through a set of examples (in [Taint Analysis Examples](#taint-analysis-examples)).

The tool will report flows from taint **sources** to **sinks**, taking in account **sanitizers** and **validators**. Those components are specified in the configuration file by the user (see [Taint Analysis Configuration](#taint-analysis-configuration)). The tool will output traces for each of the traces detected (and additional information if specified in the configuration file) (see [Taint Analysis Output](#taint-analysis-output)).

> ⚠ The taint analysis does not support usages of the `reflect` and `unsafe` packages. We explain later how to analyze programs in the presence of those, but the result is not guaranteed to be correct when the analysis raises no alarms.

## Taint Analysis Configuration
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

> 📝 Note that all strings in the `package` and `method` fields are parsed as regexes; for example, to match `Sanitizer` precisely, one should write `"^Sanitizer$"`; the `"Sanitizer"` specification will match any function name containing `Sanitizer`.

An advanced feature of the taint analysis is that you can specify dataflow summaries yourself:
```
dataflowspecs:                  # A list of dataflow specifications, where each element is a json file containing
    - "specs-mylib.json"        # dataflow specifications.

```
We explain in more detail how to write [dataflow specifications](#dataflow-specifications) later, and why the user should write dataflow specifications in some cases.

There are additional options for the outputs:
```
reportsummaries: true    # the dataflow summaries built by the analysis will be printed in a file in the reports directory

reportpaths: true        # all the paths from sources to sinks that have been discovered will be printed in individual files in the reports directory


```

## Taint Analysis Output

The `taint` tool will first print messages indicating that it finished some of the preliminary analyses before starting the first pass of the dataflow analysis. In this first pass the tool analyzes each function individually and builds a summary of how the data flows through the function. The user should see a message of the sort:
```
Starting intra-procedural analysis ...
intra-procedural pass done (0.00 s).
```
Indicating that this step has terminated. For large program, this step can take from several minutes up to an hour. The functions analyzed in this pass are all the functions that are not in the standard library, not filtered out by the `pkgfilter` option of the configuration file, and not summarize in one of the dataflow specifications file provided in the configuration.
After that, the tool will link together the dataflow summaries in an inter-procedural pass:
```
Starting inter-procedural pass...
Building inter-procedural flow graph...
--- # of analysis entrypoints: 8 ---
```
Once the inter-procedural dataflow graph has been built, the number of entry points discovered are listed. Those are all the source locations matching the source specifications given in the configuration file. If that number is not as expected, the user should check that the configuration correctly specifies the code elements that should be sources.
For each source, the tool will print a message of the form:
```
****************************** NEW SOURCE ******************************
 ==> Source: "[#467.2] (SA)call: GetSensitiveData in loadUserData"
Found at /somedir/example.go:50:17
```
Indicating the source location. If any flow of tainted data from that source location to a sink location is found, then the tool will print traces showing that flow, for example:
```
💀 Sink reached at /somedir/main.go:50:12
Add new path from "[#467.2] (SA)call: GetSensitiveData in loadUserData" to "[#23371.15] @arg 0:t20 in [#23371.14] (SA)call: LogDataPublicly(t22) in Log " <==
Report in taint-report/flow-2507865943.out
TRACE: [] /somedir/example.go:50:17
TRACE: [] /somedir/example.go:12:4
TRACE: [processData] /somedir/processing.go:120:3
TRACE: [processData] /somedir/processing.go:180:23
TRACE: [processData->t52] /somedir/main.go:324:32
TRACE: [processData->t52] /somedir/main.go:34:43
SINK: /somedir/main.go:142:3
```
The first lines indicate that a flow of tainted data has been found and it reports a representation of the instructions where the source and sinks have been found. If the configuration specifies `reportpaths : true` then the next line shows where the report is stored.
Each subsequent line starting with `TRACE` shows an approximate trace from the source to the sink, with the locations at the end and the function calls between brackets. The user can inspect those locations to see whether this trace is a false alarm, or it is a path that can occur in some execution of the program.
Finally, the tool prints the location of the sink. In some cases, the precise locations will not be available and the user will see a dash `-` printed instead of the location.

> ⚠ The tool will report important warnings during this analysis step. This indicates that some unsupported feature of Go has been encountered, and the final result is not guaranteed to be correct if no taint flow is reported. However, when taint flows are reported, the information provided by the tool still indicates that there is probably a taint flow. In other words, the presence of non-supported features only threatens the correctness of a result that says "no taint flows have been detected".

Once the analysis has terminated, the tool will print a final message:
```
RESULT:
     Taint flows detected!
```
followed by a short summary of the taint flows detected, or:
```
RESULT:
    No taint flows detected ✓
```
Meaning that the input program does have any flow of tainted data from source to sink.



## Taint Analysis Examples

Taint analyses can vary a lot in their capacities. Some analyses are more geared towards precision and reporting fewer false alarms while others are geared towards soundness, that is, reporting all possible errors, or in this case, all possible flows from source to sink. Our analysis aims at the latter, which means that in some cases it may report false alarms. In the following we give examples that showcase the different types of taint flows that can be reported by the taint analysis tool. For a more in-depth understanding of the decisions made in the implementation, the technical report explains in detail how the analysis is built.

### Simple Taint Flows
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

### Inter-procedural Taint Flow

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


### Field Sensitivity

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


### Tuple Sensitivity

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


### Closures

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

### Globals

The analysis tracks the flow to globals, but it does not precisely determine a relation between the locations where globals are read and written. This means that when a global variable is written to with tainted data, then every program point that reads the global variable is considered tainted, independently of program execution order.

Consider the following example, where `y` is a global variable that is written in two locations, and read in two locations. Only the second write propagates tainted data to `y`:
```[go]
var y T // y is a global variable

func main() {
	a := example1.GenSensitiveData()
	s := T{}
	y = s
	example2.LogDataPublicly(y) // an alarm is raised here
	y = a
	example2.LogDataPublicly(y) // an alarm is raise here
}
```
In general, we do not know where the data written to a global may be read from. In this example, the tainted data written to `y` by `y = a` is assumed to be readable at any point of the program, including in the first call to `LogDataPublicly`. In this case, an alarm is raised.

> ⚠ In general, tainted data should not be written to global variables.


## Dataflow Specifications

Dataflow specifications allow the user to specify dataflows for functions in their program. The analysis tool will skip analyzing those functions, loading the dataflow specified by the user instead. There are two kinds of user-specified dataflow summaries: summaries for functions, which specify the flow of data through a single function, and summaries for interface methods, which specify the flow of data through any of the interface method's implementation. The user must make sure that:
- in the case of a single function summary, the specified data flows subsumes any possible data flow in the function implementation
- for an interface method summary, the specified data flows subsumes any possible data flow, for any possible implementation

There are two reasons a user may want to specify a data flow summary:
- for performance: the analysis of some functions can take a lot of time, even though the flows of data can be summarized very succintly. This is the case for functions that have complex control flow and manipulate many data structures. It is also useful to summarize simple interfaces because this reduces the complexity of the call graph: a set of calls to every implementation of the interface is replaced by a single call to the summary for interface methods that are summarized by the user.
- for soundness: the analysis does not support reflection and some uses of the unsafe package. If a function uses those packages, then it should be summarized by the user. The analysis will raise alarms whenever some unsupported feature of the language is encountered during the analysis.

Dataflow specifications are json files that contain a list of specifications. Each specification is a structure that contains either an `"InterfaceId"` or an `"ObjectPath"`, along with a dictionary `"Methods"`. If an interface id is specified, then the dataflow specifications for each of the methods are interpreted as specifications for the interface methods, i.e. they specify every possible implementation of the interface. For example, consider the following dataflow specifications:
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


## Using Escape Analysis

The dataflow analysis does not support concurrency by default, meaning that it is unsound in the presence of concurrent 
threads (or goroutines). However, it can use the escape analysis built in Argot to check the validity of this assumption, and raise an 
alarm whenever the assumption that *concurrency does not interfere with dataflow* is not met. In other words, this will raise a warning when the flow of data from a 
source may interact with a memory location that is not thread-local.

To enable the escape analysis, use the following option in the config file:
```yaml
useescapeanalysis: true
```
Then if any tainted data *escapes* the thread it originates from, the tool will print those locations at the end of its
output.
For example, try running `./bin/taint -config testdata/src/taint/sample-escape/config.yaml testdata/src/taint/sample-escape/main.go`, 
you should see some output similar to:
```
[INFO]  RESULT:
                No taint flows detected ✓
[ERROR] ESCAPE ANALYSIS RESULT:
                Tainted data escapes origin thread!
[WARN]  Data escapes thread in function main:
        S: [SSA] *t18 = t0
                argot/testdata/src/taint/sample-escape/main.go:45:15
        Source: [SSA] source1()
                argot/testdata/src/taint/sample-escape/main.go:41:14

```
Indicating that no taint flow was detected, but tainted data escapes the thread it was generated in, which is a threat
to the soundness of the analysis. In this case, the data may indeed flow to a sink! In general, always sanitize the 
data before interacting with other goroutines to avoid such cases.