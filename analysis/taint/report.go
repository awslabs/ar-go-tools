// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package taint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/token"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/internal/colors"
)

// addCoverage adds an entry to coverage by properly formatting the position of the visitorNode in the context of
// the analyzer state
func addCoverage(c *dataflow.AnalyzerState, elt *dataflow.VisitorNode, coverage map[string]bool) {
	pos := elt.Node.Position(c)
	if coverage != nil {
		if c.Config.MatchCoverageFilter(pos.Filename) {
			s := fmt.Sprintf("%s:%d.1,%d.%d 1 1\n", pos.Filename, pos.Line, pos.Line, pos.Column)
			coverage[s] = true
		}
	}
}

// reportCoverage writes the coverage data contains in the coverage map to the coverageWriter
// The strings in the coverage map are sorted and then written to the coverage writer
func reportCoverage(coverage map[string]bool, coverageWriter io.StringWriter) {
	if coverageWriter != nil {
		var cov []string
		for covered := range coverage {
			cov = append(cov, covered)
		}
		sort.Slice(cov, func(i int, j int) bool { return cov[i] < cov[j] })

		for _, line := range cov {
			coverageWriter.WriteString(line)
		}
	}
}

// reportTaintFlow reports a taint flow by writing to a file if the configuration has the ReportPaths flag set,
// and writing in the logger
func reportTaintFlow(c *dataflow.AnalyzerState, source dataflow.NodeWithTrace, sink *dataflow.VisitorNode) {
	c.Logger.Infof(" 💀 Sink reached at %s\n", colors.Red(sink.Node.Position(c)))
	c.Logger.Infof(" Add new path from %s to %s <== \n",
		colors.Green(source.Node.String()), colors.Red(sink.Node.String()))
	sinkPos := sink.Node.Position(c)
	if callArg, isCallArgsink := sink.Node.(*dataflow.CallNodeArg); isCallArgsink {
		sinkPos = callArg.ParentNode().Position(c)
	}
	if c.Config.ReportPaths {
		tmp, err := os.CreateTemp(c.Config.ReportsDir, "flow-*.out")
		if err != nil {
			c.Logger.Errorf("Could not write report.")
		}
		defer tmp.Close()
		c.Logger.Infof("Report in %s\n", tmp.Name())

		tmp.WriteString(fmt.Sprintf("Source: %s\n", source.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", source.Node.Position(c)))
		tmp.WriteString(fmt.Sprintf("Sink: %s\n", sink.Node.String()))
		tmp.WriteString(fmt.Sprintf("At: %s\n", sinkPos))

		nodes := []*dataflow.VisitorNode{}
		cur := sink
		for cur != nil {
			nodes = append(nodes, cur)
			cur = cur.Prev
		}

		tmp.WriteString(fmt.Sprintf("Trace:\n"))
		for i := len(nodes) - 1; i >= 0; i-- {
			tmp.WriteString(fmt.Sprintf("%s\n", nodes[i].Node.Position(c).String()))
			c.Logger.Infof("%s - %s",
				colors.Purple("TRACE"),
				dataflow.NodeSummary(nodes[i].Node))
			c.Logger.Infof("%s - %s [%s] %s\n",
				"     ",
				dataflow.NodeKind(nodes[i].Node),
				dataflow.FuncNames(nodes[i].Trace),
				nodes[i].Node.Position(c).String())
		}
		c.Logger.Infof("-- SINK: %s\n", sinkPos.String())
	}
	// Demo visualization output
	if c.Config.ReportPaths {
		tmp, err := os.CreateTemp(c.Config.ReportsDir, "flow-*.html")
		if err != nil {
			c.Logger.Errorf("Could not write report.")
		}
		defer tmp.Close()
		c.Logger.Infof("HTML Report in %s\n", tmp.Name())

		// cardSources has the source code we want to display in each flow card
		cardSources := []string{}
		// Card data is the [start, end] indices within the source that we want to link with arrows.
		cardData := [][]int{}

		nodes := []*dataflow.VisitorNode{}
		cur := sink
		for cur != nil {
			nodes = append(nodes, cur)
			cur = cur.Prev
		}
		cardIndex := 0
		for i := len(nodes) - 1; i >= 0; i-- {
			pos := nodes[i].Node.Position(c)
			if callArg, isCallArgsink := sink.Node.(*dataflow.CallNodeArg); i == 0 && isCallArgsink {
				pos = callArg.ParentNode().Position(c)
			}
			if pos.Filename == "-" {
				continue
			}
			src, offset := getSourceAround(pos, c.Program.Fset)
			link := ""
			amazonSrc := strings.Index(pos.Filename, "/amazon-ssm-agent/")
			if amazonSrc != -1 {
				relativeFile := pos.Filename[amazonSrc+len("/amazon-ssm-agent/"):]
				href := fmt.Sprintf("https://code.amazon.com/packages/Amazon-ssm-agent/blobs/heads/Credens/--/%s#L%d", relativeFile, pos.Line)
				link = fmt.Sprintf(`<a class="codelink" href="%s">🡵</a>`, href)
			}
			cardSources = append(cardSources, fmt.Sprintf(`<div class="flow-card" id="card%d">%s<pre><code class="language-go">%s</code></pre></div><!-- line %d -->`, cardIndex, link, src, pos.Line))
			cardData = append(cardData, []int{offset, offset})
			cardIndex += 1
		}

		d, _ := json.Marshal(cardData)
		report := strings.ReplaceAll(htmlReport, "$CARD_DATA", string(d))
		report = strings.Replace(report, "$FLOW_CARDS", strings.Join(cardSources, "\n<div class=\"spacer\"></div>\n"), 1)
		tmp.WriteString(report)
	}
}

func getSourceAround(p token.Position, fset *token.FileSet) (src string, offset int) {
	f, err := os.Open(p.Filename)
	if err != nil {
		return "?", 0
	}
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	line := 0
	lines := []string{}
	specificLine := 0
	offsetInLine := 0
	for fileScanner.Scan() {
		line += 1
		if line >= p.Line-2 && line <= p.Line+2 {
			if line == p.Line {
				specificLine = len(lines)
			}
			offsetInLine = p.Column - 1
			lines = append(lines, fileScanner.Text())
		}
	}
	// Remove leading blank lines
	for specificLine > 0 && len(strings.TrimSpace(lines[0])) == 0 {
		lines = lines[1:]
		specificLine = specificLine - 1
	}
	for i := 0; i < specificLine; i++ {
		offsetInLine += len(lines[i]) + 1
	}
	return strings.ReplaceAll(strings.Join(lines, "\n"), "\t", " "), offsetInLine
}

var htmlReport = `
<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/default.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/languages/go.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/leader-line-new@1.1.9/leader-line.min.js"></script>
<style>
pre {
    margin: 0;
}
pre code.hljs {
    overflow: hidden;
}
.flow-card  {
    max-width: 500px;
    border-radius: 5px;
    border: 2px solid #EED;
	overflow: hidden;
	position: relative;
}
.spacer {
    height: 30px;
}
.flow-anchor {
    background: #DDD;
}
.hljs {
    background: none;
}
.codelink {
	position: absolute;
	right: 5px;
	text-decoration: none;
}
</style>
</head>
<body>
<div>
$FLOW_CARDS
</div>
<script>
cardData = $CARD_DATA;
function walk(node, o) {
    // console.log("walking", node, o)
    if (o == 0) { return {node:node, offset: 0}};
    // type 1 is node such div, pre, etc
    if (node.nodeType == 1) {
        return walk(node.firstChild, o)
    }
    // type 3 is text
    if (node.nodeType == 3) {
        if (o <= node.length)
            return {node:node, offset: o}
        o -= node.length
    }
    while (node.nextSibling == null) {
        node = node.parentNode
    }
    // console.log("iterating", node.nextSibling)
    return walk(node.nextSibling, o)
}
function range(node, a, b) {
    let r = document.createRange();
    var {node:start, offset:offsetStart} = walk(node, a);
    var {node:end, offset:offsetEnd} = walk(node, b);
    r.setStart(start, offsetStart);
    r.setEnd(end, offsetEnd);
    return r
}
function addAnchor(cardName, s, e, anchorName) {
  var c = document.getElementById(cardName).querySelector("pre code");
  var r = range(c, s, e)
  var a = document.createElement("a")
  a.className="flow-anchor"
  a.id = anchorName;
  a.appendChild(r.extractContents());
  r.insertNode(a)
  return a
}

document.addEventListener('DOMContentLoaded', (event) => {
  document.querySelectorAll('pre code').forEach((block) => {
    hljs.highlightElement(block);

  });
  for (var i = 0; i < cardData.length; i ++) {
    addAnchor("card" + i, cardData[i][0], cardData[i][1], "a" + i);
    if (i > 0) {
        new LeaderLine({start: document.getElementById("a" + (i-1)), end: document.getElementById("a" + i), startSocket: 'bottom', endSocket: 'top', path: 'arc', color: 'rgba(30, 130, 250, 0.5)', dash: {animation: {duration: 3000, timing: 'linear'}}})
    }
  }
});
</script>
</body>
</html>
`
