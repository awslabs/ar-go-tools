
# May Panic Analysis

The "may panic" analysis tool `maypanic` performs an analysis to determine whether each function that is launched as a goroutine `recover()`s all panics. Failure to recover from a panic in the top function of a goroutine will result in the Go runtime [terminating the program](https://go.dev/blog/defer-panic-and-recover). An example invocation is:

```
$ maypanic maypanic.go
Reading sources
Analyzing
unrecovered panic in command-line-arguments.callFunc
  command-line-arguments.callFunc
  maypanic.go:7:6
  created by maypanic.go:4:2
Found 1 unrecovered panics
```
The above output is a possible result if the maypanic.go file contains:

```go
package main

func main() {
	go callFunc()
}

func callFunc() {
    // no recover()
	doPanic()
}

func doPanic() {
	panic("Panic in doPanic")
}
```

If we change `callFunc()` to:
```go
func callFunc() {
	defer func() {
		if x := recover(); x != nil {
			// do nothing with error
		}
	}()
	doPanic()
}
```
then the error is considered handled. This tool does not enforce any particular action when recovering a panic, only that it is not allowed to be propagated to the root of the goroutine. This tool also does not enforce that code that recovers (or further deferred actions) does not panic; thus recovery code that panics may still cause program termination.

## Running the maypanic tool
The maypanic function takes options, followed by the go files to analyze.
```
maypanic [OPTIONS] source.go
maypanic [OPTIONS] source1.go source2.go
maypanic [OPTIONS] package...
```

The use with packages requires the packages to be accessible on the GOPATH.

The command may be prefixed with assignments GOOS and/or GOARCH to analyze a different architecture:
```
GOOS=windows GOARCH=amd64 maypanic source.go
```

## Options
Options that may be passed to maypanic:

- `-build VALUE`
  Options controlling the SSA builder. These options are intended to debug the SSA construction processes and generally should not be used when invoking `maypanic`.
  The value is a sequence of zero or more of these letters:
  - `C`       perform sanity \[C\]hecking of the SSA form.
  - `D`       include \[D]ebug info for every function.
  - `P`       print \[P]ackage inventory.
  - `F`       print \[F]unction SSA code.
  - `S`       log \[S]ource locations as SSA builder progresses.
  - `L`       build distinct packages seria\[L]ly instead of in parallel.
  - `N`       build \[N]aive SSA form: don't replace local loads/stores with registers.
  - `I`       build bare \[I]nit functions: no init guards or calls to dependent inits.
  - `G`       instantiate \[G]eneric function bodies via monomorphization
- `-exclude PATH` Path to exclude from analysis. May be supplied multiple times to ignore multiple paths.
- `-json` Output results as a list of JSON objects. Example:
```json
[{"Description":"unrecovered panic","GoRoutine":{"Function":"command-line-arguments.callFunc","Filename":"maypanic.go","Line":7,"Column":6},"Creators":[{"Function":"","Filename":"maypanic.go","Line":4,"Column":2}]}]
```
- `-tags TAGS...` A list of build tags to consider satisfied during the build. For more information about build tags, see the description of build constraints in the documentation for the go/build package
