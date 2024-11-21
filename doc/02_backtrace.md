# Backtrace Analysis

The "backtrace" analysis tool `backtrace` performs a whole program, backwards interprocedural dataflow analysis on the input program that is given. It is not necessary to understand those terms in order to use the tool. In this section we focus on explaining the user interface of the backtrace tool and give examples of what it can analyze. To understand how the backtrace analysis works, the reader should refer to the technical report (work in progress). Here we explain *how to use the backtrace analysis tool* through a set of examples (in [Backtrace Analysis Examples](#backtrace-analysis-examples)).

The tool will report backwards data flows from ***backtrace-points***, which are the functions from which the analysis should identify backwards data flows (traces). Those components are specified in the configuration file by the user (see [Backtrace Analysis Configuration](#backtrace-analysis-configuration)). The tool will output traces for each of the traces detected (and additional information if specified in the configuration file) (see [Backtrace Analysis Output](#backtrace-analysis-output)). The analysis entry points are all the arguments to all the calls of the backtrace-point functions. A trace represents a data flow path through the program backwards from an entrypoint. This analysis is guaranteed to report every possible backwards data flow from an entrypoint.

A trace terminates for a specific entrypoint when an instruction no longer has any inward data flow paths. For example, a trace which reaches the function call argument `f("end")` will end---the string constant `"end"` has no more inward data flow paths because no instructions write to it.

> ⚠ The backtrace analysis does not support usages of the `reflect` and `unsafe` packages. We explain later how to analyze programs in the presence of those, but the result is not guaranteed to be correct when the analysis raises no alarms.

## Backtrace Analysis Configuration
On top of the configuration options listed in the common fields, the user can specify backtrace analysis (or program slicing) problems. The configuration file accepts an option `slicing-problems` that is a list of slicing problems. Each slicing problem must set the *backtrace-points* , which identify the functions from which the analysis should find all the backwards data flows.

Below is an example of a config file containing one basic backtrace analysis specification (as part of `slicing-problems`):
```yaml
slicing-problems:
    - backtracepoints:                        # A list of entrypoints
        - package: "os/exec"
          method: "Command$"
```
In this configuration file, the user is trying to detect all the possible traces from calls to some function `Command` in a package matching `os/exec`. The tool will treat all the arguments to all the calls to `os/exec.Command` as entry points, and will report any trace from some data source to the code locations matching some `backtracepoint`.

A slicing problem can also be defined with the `must-be-static` option set to true:
```yaml
slicing-problems:  
  - must-be-static: true
    backtracepoints:
      - package: "regexp"
        method: "MustCompile"
```
With that setting, the tool will report any flow of data from a source of data that is not static to the entry points. If there is any flow found, then this is an error; in the example above, the analysis returns an error if `regexp.MustCompile` has an argument that is not entirely statically defined (i.e. constants).

> 📝 Note that all strings in the `package` and `method` fields are parsed as regexes; for example, to match `F` precisely, one should write `"^F"`; the `"backtracepoints"` specification will match any function name containing `F`.

An advanced feature of the backtrace analysis is that you can specify dataflow summaries yourself:
```yaml
dataflow-problems:
  dataflow-specs:                  # A list of dataflow specifications, where each element is a json file containing
    - "specs-mylib.json"        # dataflow specifications.

```
We explain in more detail how to write [dataflow specifications](01_taint.md#dataflow-specifications) in the `taint` tool documentation, and why the user should write dataflow specifications in some cases. The `backtrace` tool uses dataflow specifications in the same way the `taint` tool does.

There are additional options for the outputs:
```yaml
options:
  report-summaries: true    # the dataflow summaries built by the analysis will be printed in a file in the reports directory
```

## Backtrace Analysis Output

The `backtrace` tool will first print messages indicating that it finished some of the preliminary analyses before starting the first pass of the dataflow analysis. In this first pass the tool analyzes each function individually and builds a summary of how the data flows through the function. The user should see a message of the sort:
```
[INFO] Starting intra-procedural analysis ...
[INFO] intra-procedural pass done (0.00 s).
```
Indicating that this step has terminated.
After that, the tool will link together the dataflow summaries in an inter-procedural pass:
```
[INFO] Starting inter-procedural pass...
[INFO] Building inter-procedural flow graph...
[INFO] --- # of analysis entrypoints: 8 ---
```
Once the inter-procedural dataflow graph has been built, the number of entry points discovered are listed. Those are all the arguments to the function calls matching the backtrace-points specifications given in the configuration file. If that number is not as expected, the user should check that the configuration correctly specifies the code elements that should be backtrace-points.
For each source, the tool will print a message of the form:
```
[INFO] ****************************** ENTRYPOINT ******************************
[INFO] ==> Node: "[#584.4] @arg 0:name in [#584.3] (SA)call: os/exec.Command(name, args...) in runcmd "
[INFO] Found at /somedir/example.go:50:17
```
Indicating the entrypoint.

> ⚠ The tool will report important warnings during this analysis step. This indicates that some unsupported feature of Go has been encountered, and the final list of traces is not guaranteed to be exhaustive. However, when traces are reported, the information provided by the tool still indicates that there is probably a trace.

Once the analysis has terminated, the tool will print a final message:
```
[INFO] RESULT:
[INFO]     Backtraces detected!
```
followed by list of traces, or:
```
[INFO] RESULT:
[INFO]    No traces detected
```
Meaning that the input program does have any data flows backwards from any of the backtrace-points. This likely means that the analysis was misconfigured and the backtrace-points are not present in the input program.

If any backwards flow of data from an entrypoint is found, then the tool will print traces showing that flow, for example:
```
[INFO] Trace:
[INFO]	"[#576.1] @arg 0:"ls4":string in [#576.0] (SA)call: runcmd("ls4":string, nil:[]string...) in foo " at -
[INFO]	"[#584.0] parameter name : string of runcmd [0]" at /somedir/example.go:71:13
[INFO]	"[#584.4] @arg 0:name in [#584.3] (SA)call: os/exec.Command(name, args...) in runcmd " at /somedir/example.go:50:17
```
The first line of the trace represents the "source" of the data flow to the backtrace analysis entrypoint. In this example, data flows from the string literal `"ls4"` supplied as an argument to the function call `runcmd("ls4", nil)` in function `foo`. The function call argument then flows to the parameter `name` in the function definition of `runcmd`. Finally, the parameter `name` is used to call the backtrace entrypoint `os/exec.Command`.


## Backtrace Analysis Examples

### Simple Data Flows

Our backtrace analysis in general assumes that any operation propagates data flow.
```go
func main() {
    x := example1.GetSensitiveData() // no data flows backwards from `x` in this context so the analysis terminates
    y := "(" + x + ")" // data flows backwards from `y` to `x`
    example2.LogDataPublicly(y) // analysis entrypoint is `y`
}
```

In general, the analysis is conservative in how it propagates data: for example, if a cell of a slice gets modified, then the entire slice is considered modified, or if one entry in a map is modified, then the entire map is viewed as modified. The analysis also tracks aliases, and therefore modifying a variable will modify all its aliases. Modification is another way to refer to data flow: if `x` modifies `y`, then data flows forwards from `x` to `y` and backwards from `y` to `x`.

### Inter-procedural Data Flow

The backtrace analysis implemented in Argot is *inter-procedural*: the flow of data is tracked across function calls, as opposed to within a single function.
```go
func generate() *A {
    x := example1.GetSensitiveData() // no data flows backwards from `x` in this context so the analysis terminates
    return x // data flows backwards from `return x` to `x := example1.GetSensitiveData()`
}

// Copy Data field from src to dest
func copyData(src *A, dest *A) {
    dest.Data = src.Data // data flows backwards from `dest` to `src`
}


func main() {
    a := generate() // data flows backwards from `a` to the return value of `generate()`
    b := NewA() // no data flows backwards from `x` in this context so the analysis terminates
    copyData(a,b) // data flows backwards from `b` to `a`
    example2.LogDataPublicly(b) // analysis entrypoint is `b`, data flows backwards to `b` in `copyData(a,b)` and also to `b := NewA()`
}

```

The `backtrace` tool will report traces given the configuration example given previously and the snippet of code above in some context where all functions are properly defined. Detecting the types of data flows indicated in the comments of this example would not be possible without an inter-procedural analysis.

The backtrace analysis tool can detect such flows with many intermediate calls.

> 📝 To limit the size of the traces reported by the tool, one can limit how many functions deep the trace can be using the `unsafe-max-depth: [some integer]` option in the configuration file. Note that if this option is used, then the tool may not report some traces. In the previous example, one trace would not be reported if the configuration file sets `unsafe-max-depth: 2`.


### Closures

[Closures](https://go.dev/tour/moretypes/25) are functions that can reference variables (*bound* variables) from outside their body. This referencing makes the backtrace analysis more complicated, as the data may flow from aliases of the variables *bound* by a closure to the point where the closure is executed. Our tool is able to trace the flow of data in the presence of closures.

For example, in the following:
```go
func example3prep() func(string) string {
	lparen := "("
	rparen := ")"
	parenthesize := func(a string) string { return lparen + a + rparen } // rparen is captured
	rparen = example1.GetSensitiveData() // rparent is modified after being captured
	return parenthesize
}

func example3() {
	closure := example3prep()
	x := closure("A") // when closure is called, rparent was modified, so x is modified
	example2.LogDataPublicly(x)
}
```
When the closure is created, it captures the variable `rparen`, which is initially not modified (it is equal to `")"`). After the closure has been created and assigned to the `parenthesize` variable, `rparen` is modified. This means that any subsequent call to `parenthesize` will read the modified value of `rparen` and return it. This is properly tracked when `closure` is called, resulting in modified data in `x`.

The backwards dataflow analysis is able to find a trace from `example1.GetSensitiveData()` to `x` in `example2.LogDataPublicly(x)` because it considers data flow in closures.

### Globals

The analysis tracks the flow to globals, but it does not precisely determine a relation between the locations where globals are read and written. This means that when a global variable is written to, then there is a data flow to every program point that reads the global variable, independently of program execution order. In the backwards direction, a global read has a backwards data flow to every write to that variable.

Consider the following example, where `y` is a global variable that is written in two locations, and read in two locations. Only the second write propagates data to `y`:
```go
var y T // y is a global variable

func main() {
	a := example1.GenSensitiveData()
	s := T{}
	y = s
	example2.LogDataPublicly(y)
	y = a
	example2.LogDataPublicly(y)
}
```
In general, we do not know where the data written to a global may be read from. In this example, the statements `y = a` and `y = s` will appear in every trace from `example2.LogDataPublicly(y)` because the analysis must consider every data flow from the global read of `y` in `example2.LogDataPublicly(y)` to the statements that write to `y`.
