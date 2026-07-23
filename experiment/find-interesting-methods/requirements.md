# Finding "interesting" methods to summarize

This script finds "interesting" methods (i.e., Go functions/methods) given a set of taint flow problems for a single target.

The on-demand taint flow analysis computes taint flows that are reachable from a *source*, which is specified in a taint flow problem. A taint flow problem can have multiple sources. The analysis taints each source and uses an inter-procedural taint flow analysis to compute where taint flows to within each function containing a source. When taint reaches a call-site, the analysis *summarizes* the *intra*-procedural flows of each possible callee (e.g., an interface can have multiple concrete method implementations, so the analysis summarizes each implementation).

## Classifying "interesting" methods

An interesting method is a method, to which tainted data flows, that causes a state space explosion in the taint analysis *or* could not be soundly analyzed.

*Potential* causes of state space explosion include:
- large number of intra-procedural values (e.g., >1,000 since the cutoff is 10,000)
- the intra-procedural analysis taking longer than ~5 seconds for a function, implying complex intra-procedural flows
- taint flowing to a global variable
- taint flowing to the call-site of an interface method with more than 10 callees
- analysis losing calling context information due to imprecision (usually because of the pointer analysis)
- reaching a calling context depth greater than 10 methods
- encountering a loop in the call-graph (e.g., recursion)

The causes of unsoundness/incompleteness specific to the taint analysis are:
- timing out
- internal error
- concurrency (e.g., via a `go` statement)
- unbounded `defer`s (computed via the "defers" analysis in Argot)
- recover (e.g., via the `recover` statement)
- reaching the maximum calling context depth (specified by the Argot configuration)

Note that the above list does not include causes of unsoundness in underlying analyses such as the pointer analysis. This is because the soundness checker uses the same pointer analysis as the taint analysis. For example, assume that there's an "interesting" method that has a `go` statement (i.e., may have concurrency). The idea is that even if the soundness checker determines that the method's taint flow summary is "soundy" (i.e., it uses a feature of Go that makes the pointer analysis results potentially unsound), this "soundy" summary is *more* trustworthy than a "soundy" *computed* taint flow summary from the taint analysis (because the taint analysis is flow-sensitive and cannot soundly compute taint flows in the presence of concurrency).
