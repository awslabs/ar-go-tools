
# Defer Analysis

The defer analysis tool `defer` performs an analysis on the defer statements to determine whether they are bounded, i.e. whether only a fixed maximum number of deferred functions are executed at function end. An example invocation is:

```
$ defer unbounded.go
Reading sources
Analyzing
Unbounded defer stack in main (main, unbounded.go:5:6)
5208 functions had bounded defers
```
The above output is a possible result if the unbounded.go file contains:

```go
package main
import "fmt"
func main() {
	for i := 0; i < 100; i++ {
		defer func(i int) {
			fmt.Printf("Iter: %d\n", i)
		}(i)
	}
}
```
The result, `Unbounded defer stack`, refers to the fact that the defer statement occurs inside a loop and thus may in theory be executed multiple times. (The analysis does not attempt to reason about whether the loop has a fixed number of iterations, as in this example.)

The analysis also reports the number of functions that did have provably bounded defers. This number includes functions from the standard library and any dependencies, such as the `fmt` library used here.

## Running the defer tool
The defer takes options, followed by the go files to analyze.
```
defer [OPTIONS] source.go
defer [OPTIONS] source1.go source2.go
defer [OPTIONS] package...
```

The use with packages requires the packages to be accessible on the GOPATH.

The command may be prefixed with assignments GOOS and/or GOARCH to analyze a different architecture:
```
GOOS=windows GOARCH=amd64 defer source.go
```

## Options
Options that may be passed to defer:

- `-build VALUE`
  Options controlling the SSA builder. These options are intended to debug the SSA construction processes and generally should not be used when invoking `defer`.
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
- `-tags TAGS...` A list of build tags to consider satisfied during the build. For more information about build tags, see the description of build constraints in the documentation for the go/build package
- `-verbose` Enables verbose output.
