
# ARGOT: Automated Reasoning Go Tools

The Go programming language is a high-level programming language that is geared towards readability and usability for programmers aiming for highly performant distributed applications. Go is used to implement services and client-side functionality. In order to ensure that those programs are safe, programmers will need to rely on program analysis tools in order to automate the enforcement of safety properties.

## Problem

Program analysis tools can help developers safeguard their code against vulnerabilities, but also understand their code by taking different views of the program they write. Many of the analyses one could require can reuse the same underlying algorithms and reuse data obtained by other analyses, and successful approaches at designing analysis tools have consisted in packaging several analyses together to maximize reuse and provide more functionality to the user.

Many analyses have been implemented for the Go language in publicly available tools ([Go vulnerability checking](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
[Go vet](https://pkg.go.dev/cmd/vet), [Go Flow Levee](https://github.com/google/go-flow-levee)), but those analyses have limitations and their use case does not match our goals.
We need analyses that ensure the [soundness](https://cacm.acm.org/blogs/blog-cacm/236068-soundness-and-completeness-with-precision/fulltext) of their result, that is, they must ensure that if the code contains any error or any vulnerability, then an alarm will be raised. This is not the case for analyses that do only code scanning, which consists only in identifying known patterns in the code. A lot of analyses in Argot can also be used as simple checks by using some of the `unsafe-` options which usually reduces the number of false positives, at the expense of soundness.

## Solution

The Automated Reasoning Go Tools (Argot) is an experimental program analysis tool set, which at its core implements a whole-program [dataflow analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) upon which other analyses are built. The main feature of this tool set is a tool for [**taint analysis**](https://en.wikipedia.org/wiki/Taint_checking), which is an approach to verifying that no sensitive data coming from a source reaches a function that should not handle such sensitive data. The tool set also contains functionality to analyze dependency imports, reachable functions or apply a backward dataflow analysis, among others.




## Overview

### Tools in Argot

The following tools are included in Argot:
- the `taint` tool allows you to perform taint analysis in your program (see [Taint Analysis](01_taint.md#taint-analysis)).
- the `backtrace` tool allows you to find all the backwards data flows from a function call (see [Backtrace Analysis](02_backtrace.md#backtrace-analysis)).
- the `cli` is an interactive analysis tool, which lets the user run multiple analyses on the program and inspect various levels of debugging information (see [Argot CLI](03_argotcli.md#argot-cli)). This tool is intended for the advanced user who understands the underlying program representations more in detail.
- the `compare` tool, which can be used to compare the results of different reachability analyses together, on different platforms. This is useful for the user who wants to make sure the results given by some of the analyses are consistent with their assumptions, or the user that is trying to eliminate unneeded functions or dependencies (see [Compare Tool](04_compare.md#compare-tool)).
- the `defer` tool runs an analysis that computes the possible deferred functions that can run at each return point of a function (see [Defer Analysis](05_defer.md#defer-analysis)).
- the `dependencies` tool scans for the input package's dependencies and returns the list of dependencies along with the count of reachable functions within each dependency (see [Dependencies](06_dependencies.md#dependency-scanner)).
- the `maypanic` tool inspects the input packages to find goroutines with unrecovered panics (see [May Panic Analysis](07_maypanic.md#may-panic-analysis)).
- the `packagescan` tool scans the input packages to find usages of specific packages in the code, such as usages of the `unsafe` package (see [Package Scanner](08_packagescan.md#package-scanner)).
- the `reachability` tool inspects the code to find which functions are reachable, and which are not (see [Reachability Tool](09_reachability.md#reachability-tool)).
- the `syntactic` tool can be used for various syntactic analyses, for example checking that some type of struct is always initialized with specific values (see [Syntactic Tool](12_syntactic.md#syntactic-tool)),
- the `render` tool can be used to render various representations of the code, such as its [Static Single Assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form) (SSA) form or its callgraph (see [Render Tool](10_render.md#render-tool)).
- the `racerg` tool, an experimental tool for data race detection (See [RacerG](11_racerg.md#racerg-sound-and-scalable-static-data-race-detector-for-go)).

These tools can be used by developers to better understand their code, through the analysis of higher-level representations. For example, one can understand how the code is organized by looking at the callgraph, which abstract away the code and retains only the caller/callee information. In general, we do not state guarantees about the correctness of these tools, except for the dataflow analyses (see [taint analysis](01_taint.md#taint-analysis) and [backtrace](02_backtrace.md#backtrace-analysis)). However, we believe the representations obtained for each of these tools are useful enough to aid programmers.

### Configuration

The tools that require a configuration file (such as the `taint` and `cli` tools) all use the same input format, which means that your configuration file can be reused across them. The goal is that the user configuration file corresponds to a specific program to analyze, and not a specific tool. The results of the different tools for the same program with the same configuration file will be consistent.
The config file is expected to be in YAML format. All fields are generally optional, unless required by a specific tool.
Some common optional fields across tools are:

```yaml
options:
  log-level: 4                         # sets the output of the tool to debug (default is 3 for info)
  pkg-filter: "some-package/.*"        # filter which packages should be analyzed  (a regex matching package name)
  coverage-filter: "other-package/.*"  # filter for which files to report coverage (a regex matching file paths)
  reports-dir: "some-dir"              # where to store reports
  report-coverage: true                # whether to report coverage, if the analysis supports it (default false)
  report-paths: true                   # whether to report paths, if the analysis reports paths (default false)
```

> 📝 The tool accepts five different settings for the logging level: 1 for error logging, 2 for warnings, 3 for info, 4 for debugging information and 5 for tracing. Tracing should not be used on large programs.


### Targets

The `taint` and `backtrace` tools of Argot support running against specific targets that can be defined in the config file (as opposed to passed in the command line).

The targets are defined in `targets`, and each target must have a `name` and a set of `files`. The file paths are taken relatively to the directory where the config file is by default, or relatively to the project root when the `option` `project-root` is defined. 
For example, we can define two targets in the following config file:
```yaml
options:
  project-root: "../"
targets:
  - name: "target1"
    files:
      - "cmd/target1/main.go"
  - name: "target2"
    files:
      - "cmd/target2/main.go"

```
This assumes the config file is in a directory next to the `cmd` directory that contains all the executables of the project.
Analysis problems that can use specific targets will have a `targets: ["target1", "target2"]` option for example. Then each tool can be run with a single argument, the config file.The `"all"` target is a special target that means the problem applies to every target.

If some file paths are specified on the command line, the targets are ignored: all the analysis problems for the tool being called are run against the target provided on the command line.

The tools that support targets also have a command line option `-targets target1,target2` that let you specify that only a subset of the targets need to be analyzed.

> See for example the config file `payload/selfcheck/config.yaml` which is an example of using the targets to run both taint and backtrace analyses.


### Tags

Some analysis problems can be identified by tags (see the [Taint](01_taint.md), [Backtrace](02_backtrace.md) and [Syntactic](12_syntactic.md) tools). Those tags allow you to uniquely identify each problem in a configuration file (the uniqueness of the tags is checked when loading a config).
The `-tag` option (for the tools that support it) lets you run the analysis for the specific problem corresponding to the tag.

For example, if we have a several taint analysis problems in the config files, such as;
```yaml
dataflow-problems:
  taint-tracking:
    - tag: problem-1
      # rest of the fields ..
    - tag: problem-2
      # rest of the fields ..
```
Then you can run `argot taint -config config.yaml -tag problem-1` to run only the analysis related to "problem1". Combined with the `-targets` options, this lets you run very specific analyses from a configuration file that may contain many without having to duplicate configuration option or targets.