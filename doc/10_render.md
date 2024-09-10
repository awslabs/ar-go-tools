
# Render Tool

The `render` tool allows the user to show the results of several intermediate representations and analyzes of a given program. It is primarily useful as a debugging tool. The tool loads the program, runs any requested analyes, and writes the results to one or more files. The tool can output:

1. The Go analysis SSA representation in a textual format.
2. The callgraph as computed by a selected construction algorithm:
    - in GraphViz format.
    - as a cross-linked HTML file.
3. The cross function dataflow graph.

For example, to dump the SSA to a folder `ssa`:

```
$ argot render -ssaout ssa file.go
Reading sources
Generating SSA in ssa
```

Then we could find, in ssa/main.ssa:

```
...
# Name: command-line-arguments.callFunc
# Package: command-line-arguments
# Location: maypanic.go:7:6
# Recover: 1
func callFunc():
0:                                                                entry P:0 S:0
	defer callFunc$1()
	t0 = doPanic()                                                       ()
	rundefers
	return
1:                                                              recover P:0 S:0
	return
...
```

## Available Outputs and Options
Each available output takes an option of the form `-*out`. Some analysis have additional options that can be supplied to tweak the algorithm. Multiple outputs can be generated at the same time, by specifying multiple output options.

### SSA
Renders the SSA representation of the program. For more information about this format, see [x/tools/go/ssa](https://pkg.go.dev/golang.org/x/tools/go/ssa).
- `-ssaout DIR` Output results in directory `DIR/`. The directory is created if it does not already exist. Each package (which may be comprised of multiple `.go` files) is written to a separate `.ssa` file.

### Callgraph
Renders a statically computed callgraph of the program, using one of several callgraph construction algorithms provided by x/tools. These analyzes have different tradeoffs of precision, speed, and soundness, as described in their documentation. The pointer analysis is the slowest but most precise, and is generally the best option. Available analyzes can be selected by `-analysis ALG`, where `ALG` is one of:
1. [`pointer`](https://pkg.go.dev/golang.org/x/tools/go/pointer) (default, preferred)
2. [`cha`](https://pkg.go.dev/golang.org/x/tools/go/callgraph/cha)
3. [`rta`](https://pkg.go.dev/golang.org/x/tools/go/callgraph/rta)
4. [`static`](https://pkg.go.dev/golang.org/x/tools/go/callgraph/static) (unsound, not recommended)
5. [`vta`](https://pkg.go.dev/golang.org/x/tools/go/callgraph/vta)

The callgraph can be output via:

- `-cgout FILE.dot`. Writes the callgraph to the given file in GraphViz format. The resulting file can be turned into a graph using GraphViz (typically through the `dot` command):
    ```
    $ argot render -cgout call.dot file.go
    $ dot -Tsvg -o call.svg call.dot
    ```
    For even moderately sized programs, the resulting callgraph can be very large, and the resulting image may be difficult to navigate.
- `-htmlout FILE.html`. Renders the callgraph as a cross-linked HTML file. This format is more suitable for exploring the callgraph of large programs, but it does not contain a visual "graph".

### Dataflow Graph
This option outputs the inter-procedural dataflow graph for a program. The construction of the graph can be configured using a config option `-config CFG.yaml`, as described in [Configuration](DESIGN.md#configuration). The graph can be rendered using:
- `-dfout FILE.dot`

The resulting graph is the same as printed by the [showdataflow](argot-cli.md#showdataflow) CLI command.

