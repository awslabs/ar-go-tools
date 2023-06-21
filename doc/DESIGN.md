# ARGOT: Automated Reasoning Go Tools

The Go programming language is a high-level programming language that is geared towards readability and usability for programmers aiming for highly performant distributed applications. Go is used to implement services and client-side functionality. In order to ensure that those programs are safe, programmers will need to rely on program analysis tools in order to automate the enforcement of safety properties.

## Problem

Program analysis tools can help developers safeguard their code against vulnerabilities, but also understand their code by taking different views of the program they write. Many of the analyses one could require can reuse the same underlying algorithms and reuse data obtained by other analyses, and successful approaches at designing analysis tools have consisted in packaging several analyses together to maximize reuse and provide more functionality to the user.

Many analyses have been implemented for the Go language in publicly available tools ([Go vulnerability checking](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
[Go vet](https://pkg.go.dev/cmd/vet), [Go Flow Levee](https://github.com/google/go-flow-levee)), but those analyses have limitations and their use case does not match our goals.
We need analyses that ensure the [soundness](https://cacm.acm.org/blogs/blog-cacm/236068-soundness-and-completeness-with-precision/fulltext) of their result, that is, they must ensure that if the code contains any error or any vulnerability, then an alarm will be raise. This is not the case for analyses that do only code scanning, which consists only in identifying known patterns in the code.

## Solution

The Automated Reasoning GO Tools (Argot) is a program analysis tool set, which at its core implements a whole-program [dataflow analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) upon which other analyses are built. The main feature of this tool set is a tool for [**taint analysis**](https://en.wikipedia.org/wiki/Taint_checking), which is an approach to verifying that no sensitive data coming from a source reaches a function that should not handle such sensitive data. The tool set also contains functionality to analyze dependency imports, reachable function or apply a backward dataflow analysis among others.






# Overview

### Tools in Argot

The following tools are included in Argot:
- the `taint` tool allows you to perform taint analysis in your program (see [Taint Analysis](taint.md))
- the `backtrace` tool allows you to find all the backwards data flows from a function call (see [Backtrace Analysis](backtrace.md))
- the `argot-cli` is an interactive analysis tool, which lets the user run multiple analyses on the program and inspect various levels of debugging information (see [Argot CLI](argot-cli.md)). This tool is intended for the advanced user who understands the underlying program representations more in detail.
- the `compare` tool, which can be used to compare the results of different reachability analyses together, on different platforms. This is useful for the user who wants to make sure the results given by some of the analyses are consistent with their assumptions, or the user that is trying to eliminate unneeded functions or dependencies.
- the `defer` tool runs an analysis that computes the possible deferred functions that can run at each return point of a function (see [Defer Analysis](defer.md)).
- the `dependencies` tool scans for the input package's dependencies and returns the list of dependencies along with the count of reachable functions within each dependency.
- the `maypanic` tool inspects the input packages to find goroutines with unrecovered panics (see [May Panic Analysis](maypanic.md)).
- the `packagescan` tool scans the input packages to find usages of specific packages in the code, such as usages of the `unsafe` package.
- the `reachability` tool inspects the code to find which functions are reachable, and which are not.
- the `render` tool can be used to render various representations of the code, such as its [Static Single Assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form) form or its callgraph (see [Render Tool](render.md)).
- the `static-commands` tool analyzes the code to find usages of `os/exec.Command` that are defined statically.

### Configuration

The tools that require a configuration file (such as the `taint` and `argot-cli` tools) all use the same input format, which means that your configuration file can be reused across them. The goal is that the user configuration file corresponds to a specific program to analyze, and not a specific tool. The results of the different tools for the same program with the same configuration file will be consistent.
The config file is expected to be in YAML format. All fields are generally optional, unless required by a specific tool.
Some common optional fields across tools are:

```[yaml]
loglevel: 4                         # sets the output of the tool to debug (default is 3 for info)
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

> 📝 The tool accepts five different settings for the logging level: 1 for error logging, 2 for warnings, 3 for info, 4 for debugging information and 5 for tracing. Tracing should not be used on large programs.





